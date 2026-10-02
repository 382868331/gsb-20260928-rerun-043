from __future__ import annotations

import shutil
from datetime import date
from pathlib import Path

import pytest

from crp.audit import cross_table_consistency, scan_leaks
from crp.batch import BatchStore
from crp.exporter import Exporter
from crp.paths import Store
from crp.pseudonym import SubjectMapping
from crp.scope import Scope
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


def _basis(result):
    import json
    return [
        json.loads(line)
        for line in (result.version_dir / "basis.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
    ]


def _basis_by_key(exporter, result, table, raw_key):
    mapping = SubjectMapping.load_or_create(exporter.store, BATCH)
    ref = mapping.record_ref(table, raw_key)
    for payload in _basis(result):
        if payload["table"] == table and payload["record_key"] == ref:
            return payload
    raise KeyError(f"{table}:{raw_key}")


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

def test_scoped_revision_only_affects_previewed_records(workspace, exporter):
    """范围化修订：预览命中记录，范围内用新规则，范围外沿用旧规则，逐条可溯。"""
    exporter.export_batch(BATCH, note="v1 执行")
    scope_raw = read_json(ROOT / "configs" / "study001_scope_v3_labs_2024.json")
    rules_raw = read_json(ROOT / "configs" / "study001_rules_v3_scoped.json")
    BatchStore(workspace).update_rules(
        BATCH, rules_raw, note="v2：仅 2024-02 起 labs 删除备注",
        scope=Scope.parse(scope_raw),
    )

    preview = exporter.preview_scope(BATCH, 2)
    labs_preview = [row for row in preview if row.table == "labs"]
    assert {row.record_key for row in labs_preview if row.matched} == {
        "PT001|V002|LDL", "PT003|V001|WBC", "PT003|V002|WBC"
    }
    assert all(row.matched_by.startswith("out_of_scope:continues_v") for row in labs_preview if not row.matched)

    result = exporter.export_batch(BATCH, note="v2 范围执行")
    assert result.reused is False
    labs = _table(result, "labs")
    wbc = next(row for row in labs if row["test_code"] == "WBC")
    assert wbc["remark"] == ""
    hba1c = next(row for row in labs if row["test_code"] == "HBA1C")
    assert "lina.example@example.com" not in hba1c["remark"]
    wbc_basis = _basis_by_key(exporter, result, "labs", "PT003|V001|WBC")
    assert wbc_basis["rules_version"] == 2
    assert wbc_basis["matched_by"].startswith("date_range:labs:")
    assert wbc_basis["actions"]["remark"] == "drop"
    assert wbc_basis["date_shift_fields"] == ["collected_at"]
    ldl = _basis_by_key(exporter, result, "labs", "PT001|V001|LDL")
    assert ldl["rules_version"] == 1 and ldl["matched_by"] == "all"
    basis = _basis(result)
    assert {b["rules_version"] for b in basis if b["table"] == "demographics"} == {1}
    basis_text = (result.version_dir / "basis.jsonl").read_text(encoding="utf-8")
    assert "PT001" not in basis_text and "PT002" not in basis_text
    assert scan_leaks(exporter.store, BATCH, result.version) == []


def test_scope_expansion_and_shrinkage_are_separate_executions(workspace, exporter):
    """同样规则内容，范围扩大/缩小分别形成新执行；比较分别报告内容与范围变化。"""
    first = exporter.export_batch(BATCH, note="v1 执行")
    rules_raw = read_json(ROOT / "configs" / "study001_rules_v3_scoped.json")
    BatchStore(workspace).update_rules(
        BATCH, rules_raw, note="v2：范围 labs", scope=Scope.parse({"tables": ["labs"]})
    )
    second = exporter.export_batch(BATCH, note="v2 执行")
    BatchStore(workspace).update_rules(
        BATCH, rules_raw, note="v3：范围扩大到 visits",
        scope=Scope.parse({"tables": ["labs", "visits"]}),
    )
    third = exporter.export_batch(BATCH, note="v3 执行")
    BatchStore(workspace).update_rules(
        BATCH, rules_raw, note="v4：范围缩回 labs",
        scope=Scope.parse({"tables": ["labs"]}),
    )
    fourth = exporter.export_batch(BATCH, note="v4 执行")

    assert [r.version for r in (first, second, third, fourth)] == [1, 2, 3, 4]
    manifests = [read_json(r.version_dir / "manifest.json") for r in (second, third, fourth)]
    assert manifests[0]["rules_fingerprint"] == manifests[1]["rules_fingerprint"] == manifests[2]["rules_fingerprint"]
    assert manifests[0]["scope_fingerprint"] != manifests[1]["scope_fingerprint"]
    assert manifests[1]["scope_fingerprint"] != manifests[2]["scope_fingerprint"]
    assert manifests[0]["plan_fingerprint"] != manifests[2]["plan_fingerprint"]

    cmp_23 = exporter.compare_versions(BATCH, 2, 3)
    assert cmp_23.rules_changed is False and cmp_23.scope_changed is True
    cmp_24 = exporter.compare_versions(BATCH, 2, 4)
    assert cmp_24.scope_changed is True and cmp_24.same_execution is False

    trail = exporter.rule_trail(BATCH)
    assert [item["version"] for item in trail] == [1, 2, 3, 4]
    assert trail[3]["scope_equal_previous"] is False


def test_reverted_rule_content_with_different_scope_keeps_decision(workspace, exporter):
    """规则内容退回早期配置但适用对象不同：保留新决定，不因配置相同合并身份。"""
    first = exporter.export_batch(BATCH, note="v1 执行")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"), note="v2 修订"
    )
    second = exporter.export_batch(BATCH, note="v2 执行")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001.json")["rules"],
        note="v3：v1 内容但仅用药表",
        scope=Scope.parse({"tables": ["medications"]}),
    )
    third = exporter.export_batch(BATCH, note="v3 执行")

    assert third.reused is False and third.version == 3
    m1 = read_json(first.version_dir / "manifest.json")
    m3 = read_json(third.version_dir / "manifest.json")
    # 用药表的规则内容退回 v1，但其它表沿用 v2：整体规则内容集合不同；
    # 身份独立由 plan 指纹保证，不因部分内容相同而合并。
    assert m3["plan_fingerprint"] != m1["plan_fingerprint"]

    basis = _basis(third)
    assert {b["rules_version"] for b in basis if b["table"] == "medications"} == {3}
    assert {b["rules_version"] for b in basis if b["table"] != "medications"} == {2}
    meds = _table(third, "medications")
    assert meds[0]["start_date"] == "2024-01-09"
    assert "note" not in _table(third, "demographics")[0]
    cmp_13 = exporter.compare_versions(BATCH, 1, 3)
    assert cmp_13.rules_changed is True
    assert cmp_13.scope_changed is True
    assert cmp_13.same_execution is False


def test_new_source_record_is_judged_against_current_scope(workspace, exporter):
    """来源新增记录：按当时范围重新判断，不借用另一批结论。"""
    exporter.export_batch(BATCH, note="v1 执行")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v3_scoped.json"),
        note="v2：仅 labs 删备注", scope=Scope.parse({"tables": ["labs"]}),
    )
    exporter.export_batch(BATCH, note="v2 执行")
    demographics = workspace.raw_dir(BATCH) / "demographics.csv"
    with demographics.open("a", encoding="utf-8", newline="") as fh:
        fh.write("PT004,陈晨,310104200101041234,13000000004,2001-01-04,女,"
                 "上海市浦东新区世纪大道100号,随访电话13000000004\n")
    third = exporter.export_batch(BATCH, note="v3：新增 PT004")

    mapping = read_json(exporter.store.private_dir(BATCH) / "mapping.json")
    pt004_pseudo = mapping["pseudonyms"]["PT004"]
    demo_basis = [b for b in _basis(third) if b["table"] == "demographics"]
    pt004_basis = next(b for b in demo_basis if b["subject_id"] == pt004_pseudo)
    assert pt004_basis["rules_version"] == 1
    demo = _table(third, "demographics")
    assert "note" in demo[0]
    pt004_row = next(row for row in demo if row["subject_id"] == pt004_pseudo)
    assert "[REDACTED]" in pt004_row["note"]
    assert scan_leaks(exporter.store, BATCH, third.version) == []


def test_explicit_record_scope_and_invalid_scope_rejected(workspace, exporter):
    exporter.export_batch(BATCH, note="v1 执行")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v3_scoped.json"),
        note="v2：明确集合",
        scope=Scope.parse(read_json(ROOT / "configs" / "study001_scope_explicit_visits.json")),
    )
    result = exporter.export_batch(BATCH, note="v2 执行")
    visit_basis = [b for b in _basis(result) if b["table"] == "visits"]
    explicit = [b for b in visit_basis if b["matched_by"].startswith("record:")]
    assert len(explicit) == 1
    assert {b["rules_version"] for b in visit_basis if not b["matched_by"].startswith("record:")} == {1}

    with pytest.raises(ValueError, match="不存在"):
        BatchStore(workspace).update_rules(
            BATCH, read_json(ROOT / "configs" / "study001.json")["rules"],
            note="v3：错误集合",
            scope=Scope.parse({"records": {"labs": ["NOT-EXIST"]}}),
        )


def test_basis_survives_retry_and_migration(workspace, exporter):
    """增量重试与迁移历史后，日期处理与公开结果仍逐条可追溯。"""
    first = exporter.export_batch(BATCH, note="v1 执行")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v3_scoped.json"),
        note="v2：范围 labs", scope=Scope.parse({"tables": ["labs"]}),
    )
    second = exporter.export_batch(BATCH, note="v2 执行")
    basis_before = (second.version_dir / "basis.jsonl").read_bytes()
    retry = exporter.export_batch(BATCH, note="重试不改写")
    assert retry.reused is True and retry.version == second.version
    assert (second.version_dir / "basis.jsonl").read_bytes() == basis_before

    exporter.store.export_index(BATCH).unlink()
    rebuilt = exporter._load_index(BATCH)
    assert [entry["version"] for entry in rebuilt["versions"]] == [1, 2]
    assert rebuilt["versions"][1]["files"].get("basis.jsonl")
    wbc = _basis_by_key(exporter, second, "labs", "PT003|V001|WBC")
    assert wbc["date_shift_fields"] == ["collected_at"]
    assert wbc["rules_version"] == 2
    assert first.version_dir.exists()
