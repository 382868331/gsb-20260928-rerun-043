from __future__ import annotations

import shutil
from datetime import date
from pathlib import Path

import pytest

from crp.audit import cross_table_consistency, scan_leaks
from crp.batch import BatchStore
from crp.exporter import Exporter
from crp.paths import Store
from crp.util import read_csv, read_json

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


def _table_path(result, name: str):
    return result.version_dir / f"{name}.csv"


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
        p.name: p.read_bytes() for p in first.version_dir.glob("*.csv") if p.name != "rule_trace.csv"
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
        p.name: p.read_bytes() for p in second.version_dir.glob("*.csv") if p.name != "rule_trace.csv"
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


def test_rules_reverted_to_old_config_still_creates_new_execution(workspace, exporter):
    """v1 -> v2 -> 改回 v1 配置（成为规则修订 v3）：第三次执行不得冒充第一次。"""
    v1 = exporter.export_batch(BATCH, note="v1 执行")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2 修订",
    )
    v2 = exporter.export_batch(BATCH, note="v2 执行")
    # 输入资料随后变化（新增 PT004），再把规则退回第一版配置。
    demographics = workspace.raw_dir(BATCH) / "demographics.csv"
    with demographics.open("a", encoding="utf-8", newline="") as fh:
        fh.write("PT004,陈晨,310104200101041234,13000000004,2001-01-04,女,"
                 "上海市浦东新区世纪大道100号,随访电话13000000004\n")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001.json")["rules"],
        note="v3 修订：退回 v1 配置",
    )
    v3 = exporter.export_batch(BATCH, note="v3 执行：旧配置+新来源")

    assert v3.reused is False and v3.version == 3
    assert v3.version != v1.version
    v1m = read_json(v1.version_dir / "manifest.json")
    v3m = read_json(v3.version_dir / "manifest.json")
    assert v3m["rules_version"] == 3
    assert v3m["rules_fingerprint"] == v1m["rules_fingerprint"]
    assert v3m["source_fingerprint"] != v1m["source_fingerprint"]
    # 新来源必须体现在本次公开结果里。
    assert len(_table(v3, "demographics")) == 4
    assert len(_table(v1, "demographics")) == 3
    # v2 的用药日期平移在退回后不再生效。
    assert "start_date" in _table(v2, "medications")[0]
    med_v2 = _table(v2, "medications")[0]
    med_v3 = _table(v3, "medications")[0]
    assert med_v3["start_date"] == "2024-01-09"
    assert med_v2["start_date"] != "2024-01-09"
    assert med_v3["end_date"] == "2024-03-12"
    assert "PT004" not in " ".join(
        p.read_text(encoding="utf-8") for p in v3.version_dir.glob("*.csv")
    )
    # 旧执行原样可查。
    assert v1.version_dir.exists() and v2.version_dir.exists()

    comparison = exporter.compare_versions(BATCH, v1.version, v3.version)
    assert comparison.rules_config_equal is True
    assert comparison.rules_changed is False
    assert comparison.rules_version_from == 1 and comparison.rules_version_to == 3
    assert comparison.source_changed is True
    assert comparison.output_equal is False
    assert comparison.same_execution is False

    trail = exporter.rule_trail(BATCH)
    assert [item["version"] for item in trail] == [1, 2, 3]
    assert [item["rules_version"] for item in trail] == [1, 2, 3]
    assert trail[2]["rules_config_equal_previous"] is False
    assert trail[2]["source_equal_previous"] is False


def test_repeated_export_is_marked_as_same_execution(exporter):
    first = exporter.export_batch(BATCH, note="首版")
    second = exporter.export_batch(BATCH, note="重跑")
    assert second.reused is True and second.version == first.version
    # 手工构造两次执行记录视角：同规则修订+同输入即同一次执行。
    index = read_json(exporter.store.export_index(BATCH))
    assert len(index["versions"]) == 1
    trail = exporter.rule_trail(BATCH)
    assert len(trail) == 1


def test_interrupted_export_leaves_clean_state_for_retry(workspace, exporter):
    first = exporter.export_batch(BATCH, note="v1 执行")
    # 模拟上次导出在写入中途被中断：残留不完整的 v002 目录，index 未登记。
    orphan = exporter.store.version_dir(BATCH, 2)
    orphan.mkdir(parents=True)
    (orphan / "demographics.csv").write_text("partial,data\n", encoding="utf-8")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2 修订",
    )
    second = exporter.export_batch(BATCH, note="v2 执行")
    assert second.reused is False and second.version == 2
    assert read_csv(second.version_dir / "demographics.csv")
    assert first.version_dir.exists()
    index = read_json(exporter.store.export_index(BATCH))
    assert [entry["version"] for entry in index["versions"]] == [1, 2]


def test_migrated_history_rebuilds_index_from_version_dirs(workspace, exporter):
    first = exporter.export_batch(BATCH, note="v1 执行")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2 修订",
    )
    second = exporter.export_batch(BATCH, note="v2 执行")
    # 迁移历史记录：index.json 丢失，只剩不可变版本目录与批次规则历史。
    exporter.store.export_index(BATCH).unlink()
    rebuilt = exporter._load_index(BATCH)
    assert [entry["version"] for entry in rebuilt["versions"]] == [1, 2]
    assert rebuilt["latest"] == 2
    assert rebuilt["versions"][0]["rules_version"] == 1
    assert rebuilt["versions"][1]["rules_version"] == 2
    # 旧执行仍可查，compare 仍可用。
    comparison = exporter.compare_versions(BATCH, first.version, second.version)
    assert comparison.rules_changed is True
    assert comparison.output_equal is False


def test_scoped_rule_revision_preview_and_per_record_basis(workspace, exporter):
    first = exporter.export_batch(BATCH, note="v1：全量旧规则")
    scope = {
        "time_range": {"start": "2024-02-01", "end": "2024-04-30"},
        "fields": {
            "visits": "visit_date",
            "labs": "collected_at",
            "medications": "start_date",
        },
    }
    preview = exporter.preview_scope(BATCH, scope)
    included = {(item["table"], item["row_number"]) for item in preview.included}
    assert ("visits", 5) in included and ("visits", 4) not in included
    assert ("medications", 4) in included and ("medications", 2) not in included

    BatchStore(workspace).update_rules(
        BATCH,
        read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2：仅 2 月起资料补充用药日期平移",
        scope=scope,
    )
    second = exporter.export_batch(BATCH, note="v2：部分资料执行")
    assert second.reused is False

    trace = _table_path(second, "rule_trace")
    decisions = read_csv(trace)
    by_location = {(row["table"], int(row["source_row"])): row for row in decisions}
    assert by_location[("visits", 4)]["rules_version"] == "1"
    assert by_location[("visits", 5)]["rules_version"] == "2"
    assert by_location[("medications", 2)]["rules_version"] == "1"
    assert by_location[("medications", 4)]["rules_version"] == "2"
    assert "适用范围" in by_location[("medications", 4)]["basis"]

    medications = _table(second, "medications")
    assert medications[0]["start_date"] == "2024-01-09"
    assert medications[2]["start_date"] != "2024-02-02"
    demographics = _table(second, "demographics")
    assert "note" in demographics[0]
    assert scan_leaks(exporter.store, BATCH, second.version) == []

    comparison = exporter.compare_versions(BATCH, first.version, second.version)
    assert comparison.rules_changed is True
    assert comparison.scope_changed is True
    assert comparison.source_changed is False
    assert comparison.output_changed is True


def test_scope_revision_is_immutable_and_new_records_are_evaluated_now(workspace, exporter):
    exporter.export_batch(BATCH, note="v1")
    med_only_scope = {"sources": ["medications"]}
    BatchStore(workspace).update_rules(
        BATCH,
        read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2：仅用药",
        scope=med_only_scope,
    )
    scoped = exporter.export_batch(BATCH, note="v2：仅用药")
    scoped_manifest = read_json(scoped.version_dir / "manifest.json")

    BatchStore(workspace).update_rules(
        BATCH,
        read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v3：同内容扩大到检验",
        scope={"sources": ["medications", "labs"]},
    )
    widened = exporter.export_batch(BATCH, note="v3：扩大范围")
    assert widened.version == 3
    widened_manifest = read_json(widened.version_dir / "manifest.json")
    assert widened_manifest["rules_fingerprint"] == scoped_manifest["rules_fingerprint"]
    assert widened_manifest["scope_fingerprint"] != scoped_manifest["scope_fingerprint"]
    assert read_json(scoped.version_dir / "manifest.json") == scoped_manifest

    labs = workspace.raw_dir(BATCH) / "labs.csv"
    with labs.open("a", encoding="utf-8", newline="") as fh:
        fh.write("PT001,V003,LDL,2024-05-02,3.1,mmol/L,新增后核对\n")
    retried = exporter.export_batch(BATCH, note="v3：新增后重跑")
    assert retried.version == 4
    assert retried.reused is False
    decisions = read_csv(_table_path(retried, "rule_trace"))
    new_row = next(
        item for item in decisions
        if item["table"] == "labs" and int(item["source_row"]) == 7
    )
    assert new_row["rules_version"] == "3"
    assert new_row["scope"] == "来源=medications,labs"

    rebuilt = exporter._load_index(BATCH)
    exporter.store.export_index(BATCH).unlink()
    rebuilt_after_migration = exporter._load_index(BATCH)
    assert [entry["scope_fingerprint"] for entry in rebuilt["versions"]] == [
        entry["scope_fingerprint"] for entry in rebuilt_after_migration["versions"]
    ]


def test_explicit_record_collection_uses_row_number_and_does_not_borrow_other_batch(workspace, exporter):
    exporter.export_batch(BATCH, note="v1")
    scope = {"records": [{"table": "demographics", "row_number": 2}]}
    preview = exporter.preview_scope(BATCH, scope)
    assert len(preview.included) == 1
    assert preview.included[0]["table"] == "demographics"
    assert preview.included[0]["row_number"] == 2

    BatchStore(workspace).update_rules(
        BATCH,
        read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2：仅首条人口学记录",
        scope=scope,
    )
    result = exporter.export_batch(BATCH, note="v2：明确集合")
    decisions = read_csv(_table_path(result, "rule_trace"))
    versions = {(item["table"], int(item["source_row"])): item["rules_version"] for item in decisions}
    assert versions[("demographics", 2)] == "2"
    assert versions[("demographics", 3)] == "1"
    assert scan_leaks(exporter.store, BATCH, result.version) == []
