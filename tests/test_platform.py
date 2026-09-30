from __future__ import annotations

import shutil
from datetime import date
from pathlib import Path

import pytest

from crp.audit import cross_table_consistency, scan_leaks
from crp.batch import BatchStore
from crp.exporter import Exporter
from crp.paths import Store
from crp.util import read_csv, read_json, write_json

ROOT = Path(__file__).resolve().parents[1]
BATCH = "STUDY-001"


@pytest.fixture()
def workspace(tmp_path: Path) -> Store:
    shutil.copytree(ROOT / "data" / "raw", tmp_path / "raw")
    return Store.create(tmp_path)


@pytest.fixture()
def exporter(workspace: Store) -> Exporter:
    BatchStore(workspace).create(read_json(ROOT / "configs" / "study001.json"))
    return Exporter(workspace)


def _table(result, name: str):
    return read_csv(result.version_dir / f"{name}.csv")


def test_export_removes_direct_identifiers(exporter):
    result = exporter.export_batch(BATCH, note="首版导出")
    demo = _table(result, "demographics")
    assert set(demo[0]) == {"subject_id", "birth_date", "sex", "note"}
    joined = "".join("".join(row.values()) for row in demo)
    for forbidden in ("张伟", "李娜", "王芳", "110101199003071234", "13800138001"):
        assert forbidden not in joined


def test_same_subject_has_one_stable_pseudonym_across_tables(exporter):
    result = exporter.export_batch(BATCH)
    linked = cross_table_consistency(exporter.store, BATCH, result.version)
    demo = {row["subject_id"] for row in _table(result, "demographics")}
    for table in ("visits", "labs", "medications"):
        assert {row["subject_id"] for row in _table(result, table)} <= demo
    assert len(linked) == 3
    for pseudo, places in linked.items():
        assert pseudo.startswith("S")
        assert len({place.split(":", 1)[0] for place in places}) >= 2


def test_date_shift_is_aligned_across_tables_and_preserves_intervals(exporter):
    result = exporter.export_batch(BATCH)
    mapping = read_json(exporter.store.private_dir(BATCH) / "mapping.json")
    pseudo_pt1 = mapping["pseudonyms"]["PT001"]
    visits = {(row["subject_id"], row["visit_id"]): row["visit_date"] for row in _table(result, "visits")}
    labs = {(row["subject_id"], row["visit_id"]): row["collected_at"] for row in _table(result, "labs")}
    assert visits == labs
    delta = (date.fromisoformat(visits[(pseudo_pt1, "V002")])
             - date.fromisoformat(visits[(pseudo_pt1, "V001")])).days
    assert delta == 64
    shifted = date.fromisoformat(visits[(pseudo_pt1, "V001")])
    assert (shifted - date(2024, 1, 8)).days == mapping["offset_days"]["PT001"]


def test_free_text_redacts_builtin_and_manual_fragments(exporter):
    result = exporter.export_batch(BATCH)
    visit_text = " ".join(row["chief_complaint"] for row in _table(result, "visits"))
    lab_text = " ".join(row["remark"] for row in _table(result, "labs"))
    med_text = " ".join(row["note"] for row in _table(result, "medications"))
    assert "13800138001" not in visit_text and "[REDACTED]" in visit_text
    assert "王建国" not in visit_text
    assert "lina.example@example.com" not in lab_text and "[REDACTED]" in lab_text
    assert "李娜" not in med_text and "广州市天河区天河路200号" not in med_text
    assert scan_leaks(exporter.store, BATCH, result.version) == []


def test_private_mapping_never_enters_public_export(exporter):
    result = exporter.export_batch(BATCH)
    public_files = {path.name for path in result.version_dir.rglob("*") if path.is_file()}
    assert "mapping.json" not in public_files
    mapping = read_json(exporter.store.private_dir(BATCH) / "mapping.json")
    all_public = " ".join(
        path.read_text(encoding="utf-8") for path in result.version_dir.rglob("*.csv")
    )
    for real_id in mapping["pseudonyms"]:
        assert real_id not in all_public


def test_repeated_export_is_byte_identical_and_reuses_version(exporter):
    first = exporter.export_batch(BATCH, note="首版导出")
    before = {p.name: p.read_bytes() for p in first.version_dir.iterdir() if p.is_file()}
    second = exporter.export_batch(BATCH, note="另一条说明不应改写旧版本")
    assert second.reused is True and second.version == first.version
    after = {p.name: p.read_bytes() for p in first.version_dir.iterdir() if p.is_file()}
    assert before == after


def test_rule_update_creates_new_version_and_keeps_old_notes(workspace, exporter):
    first = exporter.export_batch(BATCH, note="v1：保留人口学备注文本脱敏")
    v1_manifest = read_json(first.version_dir / "manifest.json")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2：删除人口学备注并补充用药日期平移",
    )
    second = exporter.export_batch(BATCH, note="v2：删除人口学备注并补充用药日期平移")
    assert second.reused is False and second.version == first.version + 1
    assert first.version_dir.exists()
    assert read_json(first.version_dir / "manifest.json") == v1_manifest
    assert "note" not in _table(second, "demographics")[0]
    assert _table(second, "medications")[0]["start_date"] != "2024-01-09"
    index = read_json(exporter.store.export_index(BATCH))
    assert [entry["note"] for entry in index["versions"]] == [
        "v1：保留人口学备注文本脱敏", "v2：删除人口学备注并补充用药日期平移",
    ]


def test_subject_column_cannot_be_dropped(workspace):
    config = read_json(ROOT / "configs" / "study001.json")
    config["rules"]["visits"].append({"field": "subject_id", "action": "drop"})
    BatchStore(workspace).create(config)
    with pytest.raises(ValueError, match="受试者关联列"):
        Exporter(workspace).export_batch(BATCH)


def test_inert_rule_change_keeps_bytes_but_records_new_execution_identity(workspace, exporter):
    """规则变化但未触发任何替换时，输出字节恰好不变：仍须产生新版本身份。"""
    first = exporter.export_batch(BATCH, note="v1：基线规则")
    v1_manifest = read_json(first.version_dir / "manifest.json")
    v1_bytes = {
        p.name: p.read_bytes() for p in first.version_dir.glob("*.csv")
    }

    config = read_json(ROOT / "configs" / "study001.json")
    # 显式 keep 与默认行为完全等价，不改变任何输出字节，但规则指纹变化。
    config["rules"]["demographics"].append({"field": "sex", "action": "keep"})
    BatchStore(workspace).update_rules(BATCH, config["rules"], note="v2：显式声明性别保留")
    second = exporter.export_batch(BATCH, note="v2：显式声明性别保留")

    assert second.reused is False
    assert second.version == first.version + 1
    assert second.rules_version == 2
    assert second.content_reused_from == first.version
    v2_manifest = read_json(second.version_dir / "manifest.json")
    assert v2_manifest["rules_version"] == 2
    assert v2_manifest["rules_fingerprint"] != v1_manifest["rules_fingerprint"]
    assert v2_manifest["source_fingerprint"] == v1_manifest["source_fingerprint"]
    assert v2_manifest["output_fingerprint"] == v1_manifest["output_fingerprint"]
    assert v2_manifest["content_reused_from"] == first.version
    v2_bytes = {
        p.name: p.read_bytes() for p in second.version_dir.glob("*.csv")
    }
    assert v2_bytes == v1_bytes
    # 旧版本、旧说明、旧规则溯源原样可查。
    assert read_json(first.version_dir / "manifest.json") == v1_manifest
    index = read_json(exporter.store.export_index(BATCH))
    assert [entry["rules_version"] for entry in index["versions"]] == [1, 2]
    assert [entry["note"] for entry in index["versions"]] == ["v1：基线规则", "v2：显式声明性别保留"]

    comparison = exporter.compare_versions(BATCH, first.version, second.version)
    assert comparison.rules_changed is True
    assert comparison.source_changed is False
    assert comparison.output_changed is False
    assert comparison.changed_files == ()


def test_compare_distinguishes_date_shift_rule_change(workspace, exporter):
    """日期平移规则变化会改变最终内容，但输入数据不变。"""
    first = exporter.export_batch(BATCH, note="v1：用药日期不平移")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2：补充用药日期平移",
    )
    second = exporter.export_batch(BATCH, note="v2：补充用药日期平移")

    comparison = exporter.compare_versions(BATCH, first.version, second.version)
    payload = comparison.to_dict()
    assert comparison.rules_changed is True
    assert comparison.source_changed is False
    assert comparison.output_changed is True
    assert "medications.csv" in comparison.changed_files
    assert payload["rules_version"] == {"from": 1, "to": 2}


def test_partial_record_addition_changes_source_and_output(workspace, exporter):
    """部分记录新增：规则不变、输入变化、输出变化，新增真实编号不得出现在公开文件。"""
    first = exporter.export_batch(BATCH, note="v1：三名受试者")
    demographics = workspace.raw_dir(BATCH) / "demographics.csv"
    with demographics.open("a", encoding="utf-8", newline="") as fh:
        fh.write("PT004,陈晨,310104200101041234,13000000004,2001-01-04,女,"
                 "上海市浦东新区世纪大道100号,健康随访电话13000000004\n")

    second = exporter.export_batch(BATCH, note="v2：新增 PT004 记录")
    assert second.reused is False and second.content_reused_from is None
    v1_manifest = read_json(first.version_dir / "manifest.json")
    v2_manifest = read_json(second.version_dir / "manifest.json")
    assert v2_manifest["rules_fingerprint"] == v1_manifest["rules_fingerprint"]
    assert v2_manifest["source_fingerprint"] != v1_manifest["source_fingerprint"]
    assert v2_manifest["output_fingerprint"] != v1_manifest["output_fingerprint"]

    demo = _table(second, "demographics")
    assert len(demo) == 4
    public_text = " ".join(
        path.read_text(encoding="utf-8") for path in second.version_dir.rglob("*.csv")
    )
    assert "PT004" not in public_text
    assert "13000000004" not in public_text and "310104200101041234" not in public_text
    assert scan_leaks(exporter.store, BATCH, second.version) == []

    comparison = exporter.compare_versions(BATCH, first.version, second.version)
    assert comparison.rules_changed is False
    assert comparison.source_changed is True
    assert comparison.output_changed is True
    assert comparison.changed_files == ("demographics.csv",)
    # 旧映射与旧说明继续可查。
    mapping = read_json(exporter.store.private_dir(BATCH) / "mapping.json")
    assert set(mapping["pseudonyms"]) >= {"PT001", "PT002", "PT003", "PT004"}
    assert read_json(first.version_dir / "manifest.json")["note"] == "v1：三名受试者"


def test_rule_revert_to_old_config_creates_independent_execution(workspace, exporter):
    """v1→v2→改回v1配置：第三次规则修订与执行必须有独立记录，不得冒充第一次执行。"""
    first = exporter.export_batch(BATCH, note="v1：基线规则")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"), note="v2：用药日期平移"
    )
    second = exporter.export_batch(BATCH, note="v2：用药日期平移")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001.json")["rules"], note="v3：改回v1配置"
    )
    third = exporter.export_batch(BATCH, note="v3：改回v1配置")

    assert third.reused is False
    assert third.version == 3 and third.rules_version == 3
    assert third.content_reused_from == first.version
    v3_manifest = read_json(third.version_dir / "manifest.json")
    v1_manifest = read_json(first.version_dir / "manifest.json")
    assert v3_manifest["rules_fingerprint"] == v1_manifest["rules_fingerprint"]
    assert v3_manifest["source_fingerprint"] == v1_manifest["source_fingerprint"]
    assert v3_manifest["output_fingerprint"] == v1_manifest["output_fingerprint"]
    assert v3_manifest["note"] == "v3：改回v1配置"
    # 旧执行原样保留，且每条执行对应独立目录。
    assert read_json(first.version_dir / "manifest.json")["note"] == "v1：基线规则"
    assert {path.name for path in exporter.store.export_dir(BATCH).glob("v*")} == {
        "v001", "v002", "v003",
    }

    comparison = exporter.compare_versions(BATCH, 1, 3)
    assert comparison.rules_changed is False
    assert comparison.source_changed is False
    assert comparison.output_changed is False
    assert comparison.same_execution is False
    assert comparison.content_reused_from_to == 1


def test_rule_revert_with_changed_source_points_at_new_source(workspace, exporter):
    """规则退回旧配置但输入资料随后变化：新执行必须溯源到新来源。"""
    first = exporter.export_batch(BATCH, note="v1：基线")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"), note="v2"
    )
    exporter.export_batch(BATCH, note="v2")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001.json")["rules"], note="v3改回v1"
    )
    with (workspace.raw_dir(BATCH) / "demographics.csv").open("a", encoding="utf-8", newline="") as fh:
        fh.write("PT004,陈晨,310104200101041234,13000000004,2001-01-04,女,上海,随访13000000004\n")
    third = exporter.export_batch(BATCH, note="v3改回v1+新数据")

    assert third.reused is False and third.content_reused_from is None
    v1 = read_json(first.version_dir / "manifest.json")
    v3 = read_json(third.version_dir / "manifest.json")
    assert v3["rules_fingerprint"] == v1["rules_fingerprint"]
    assert v3["source_fingerprint"] != v1["source_fingerprint"]
    assert v3["output_fingerprint"] != v1["output_fingerprint"]


def test_rule_trail_distinguishes_config_output_and_execution(workspace, exporter):
    """沿规则修订顺序：区分配置相同、输出相同、同一次执行。"""
    first = exporter.export_batch(BATCH, note="v1基线")
    config = read_json(ROOT / "configs" / "study001.json")
    config["rules"]["demographics"].append({"field": "sex", "action": "keep"})
    BatchStore(workspace).update_rules(BATCH, config["rules"], note="v2惰性变化")
    second = exporter.export_batch(BATCH, note="v2惰性变化")
    # 同一修订下重复导出：属于同一次执行。
    repeat = exporter.export_batch(BATCH, note="v2重复导出")
    assert repeat.reused is True and repeat.version == second.version
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001.json")["rules"], note="v3改回v1"
    )
    third = exporter.export_batch(BATCH, note="v3改回v1")

    trail = {view.rules_version: view for view in exporter.rule_trail(BATCH)}
    assert trail[1].config_same_as is None
    assert trail[1].execution_version == first.version
    assert trail[1].output_same_as is None
    assert trail[2].config_same_as is None
    assert trail[2].execution_version == second.version
    assert trail[2].output_same_as == 1
    assert trail[3].config_same_as == 1
    assert trail[3].execution_version == third.version
    assert trail[3].output_same_as == 1


def test_interrupted_export_retries_cleanly(workspace, exporter):
    """中断残留目录被清理后，重试产生新的完整执行；同修订再导出仍幂等。"""
    exporter.export_batch(BATCH, note="v1")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"), note="v2"
    )
    broken = workspace.version_dir(BATCH, 2)
    broken.mkdir(parents=True)
    (broken / "demographics.csv").write_text("残缺内容", encoding="utf-8")
    (workspace.export_dir(BATCH) / ".staging-2-leftover").mkdir()

    retried = exporter.export_batch(BATCH, note="v2重试")
    assert retried.version == 2 and retried.reused is False
    assert read_json(retried.version_dir / "manifest.json")["note"] == "v2重试"
    assert not (workspace.export_dir(BATCH) / ".staging-2-leftover").exists()
    repeat = exporter.export_batch(BATCH, note="v2再来一次")
    assert repeat.reused is True and repeat.version == 2


def test_migrated_history_is_kept_and_new_versions_continue_after_it(workspace, exporter):
    """迁移来的历史版本目录原样可查，新版本号顺延，绝不覆盖旧执行。"""
    first = exporter.export_batch(BATCH, note="v1")
    migrated = workspace.version_dir(BATCH, 7)
    shutil.copytree(first.version_dir, migrated)
    payload = read_json(migrated / "manifest.json")
    payload["version"] = 7
    payload["note"] = "迁移来的历史执行"
    write_json(migrated / "manifest.json", payload)

    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"), note="v2"
    )
    result = exporter.export_batch(BATCH, note="v2")
    assert result.version == 8
    assert read_json(migrated / "manifest.json")["note"] == "迁移来的历史执行"
    index = read_json(workspace.export_index(BATCH))
    assert {entry["version"] for entry in index["versions"]} >= {1, 8}
    assert migrated.exists()
