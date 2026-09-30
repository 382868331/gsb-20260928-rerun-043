from __future__ import annotations

import shutil
from datetime import date, timedelta
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


def _rules_v1():
    return read_json(ROOT / "configs" / "study001.json")["rules"]


def test_rule_change_with_identical_bytes_still_gets_new_identity(workspace, exporter):
    """规则调整未触发任何替换/字节差异时，也必须以新规则版本记录独立导出身份。"""
    first = exporter.export_batch(BATCH, note="v1：基线规则")
    v1_bytes = {p.name: p.read_bytes() for p in first.version_dir.iterdir() if p.suffix == ".csv"}

    noop_rules = _rules_v1()
    noop_rules["demographics"].append({"field": "sex", "action": "keep"})
    BatchStore(workspace).update_rules(BATCH, noop_rules, note="v2：显式保留 sex（不改变输出）")
    second = exporter.export_batch(BATCH, note="v2：显式保留 sex（不改变输出）")

    assert second.reused is False
    assert second.version == first.version + 1
    assert second.rules_version == 2
    assert second.content_reused_from == first.version

    v1_manifest = read_json(first.version_dir / "manifest.json")
    v2_manifest = read_json(second.version_dir / "manifest.json")
    assert v2_manifest["rules_version"] == 2
    assert v2_manifest["rules_fingerprint"] != v1_manifest["rules_fingerprint"]
    assert v2_manifest["source_fingerprint"] == v1_manifest["source_fingerprint"]
    assert v2_manifest["output_fingerprint"] == v1_manifest["output_fingerprint"]
    assert v2_manifest["content_derived_from"] == first.version

    v2_bytes = {p.name: p.read_bytes() for p in second.version_dir.iterdir() if p.suffix == ".csv"}
    assert v2_bytes == v1_bytes

    index = read_json(exporter.store.export_index(BATCH))
    assert [entry["rules_version"] for entry in index["versions"]] == [1, 2]

    comparison = exporter.compare_exports(BATCH, first.version, second.version)
    assert comparison.rules_changed is True
    assert comparison.source_changed is False
    assert comparison.output_changed is False
    assert set(comparison.table_changes.values()) == {"unchanged"}


def test_compare_distinguishes_date_shift_rule_change(workspace, exporter):
    """新增用药日期平移规则：规则与最终内容变化，但输入数据未变。"""
    first = exporter.export_batch(BATCH, note="v1：用药日期不平移")
    BatchStore(workspace).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2：删除人口学备注并补充用药日期平移",
    )
    second = exporter.export_batch(BATCH, note="v2：删除人口学备注并补充用药日期平移")

    comparison = exporter.compare_exports(BATCH, first.version, second.version)
    assert comparison.rules_changed is True
    assert comparison.source_changed is False
    assert comparison.output_changed is True
    assert comparison.table_changes["visits"] == "unchanged"
    assert comparison.table_changes["labs"] == "unchanged"
    assert comparison.table_changes["medications"] == "changed"
    assert comparison.table_changes["demographics"] == "changed"

    meds = _table(second, "medications")
    mapping = read_json(exporter.store.private_dir(BATCH) / "mapping.json")
    offset = mapping["offset_days"]["PT001"]
    assert meds[0]["start_date"] != "2024-01-09"
    assert meds[0]["start_date"] == (date(2024, 1, 9) + timedelta(days=offset)).isoformat()


def test_partial_record_addition_creates_new_version_keeps_old_provenance(workspace, exporter):
    """部分记录新增：数据与输出变化但规则不变；旧伪名映射、旧版本说明继续可查。"""
    first = exporter.export_batch(BATCH, note="v1：首批记录")
    old_mapping = read_json(exporter.store.private_dir(BATCH) / "mapping.json")
    old_manifest = read_json(first.version_dir / "manifest.json")

    labs_path = workspace.raw_dir(BATCH) / "labs.csv"
    with labs_path.open("a", encoding="utf-8", newline="") as fh:
        fh.write("PT004,V001,HBA1C,2024-03-01,6.5,%,新入组受试者首次采血\n")

    second = exporter.export_batch(BATCH, note="v2：新增 PT004 检验记录")
    assert second.reused is False
    assert second.rules_version == 1

    comparison = exporter.compare_exports(BATCH, first.version, second.version)
    assert comparison.rules_changed is False
    assert comparison.source_changed is True
    assert comparison.output_changed is True
    assert comparison.table_changes["labs"] == "changed"
    assert comparison.table_changes["demographics"] == "unchanged"

    # 旧映射继续可查且既有受试者伪名不被新数据改写
    mapping = read_json(exporter.store.private_dir(BATCH) / "mapping.json")
    for real_id, pseudo in old_mapping["pseudonyms"].items():
        assert mapping["pseudonyms"][real_id] == pseudo
    assert "PT004" in mapping["pseudonyms"]

    # 旧版本与旧说明原样保留
    assert read_json(first.version_dir / "manifest.json") == old_manifest
    index = read_json(exporter.store.export_index(BATCH))
    assert [entry["note"] for entry in index["versions"]] == [
        "v1：首批记录", "v2：新增 PT004 检验记录",
    ]

    # 公开资料（含新版本）不得带出私有身份映射
    for version in (first.version, second.version):
        version_dir = exporter.store.version_dir(BATCH, version)
        public_files = {p.name for p in version_dir.rglob("*") if p.is_file()}
        assert "mapping.json" not in public_files
        public_text = " ".join(
            p.read_text(encoding="utf-8") for p in version_dir.rglob("*.csv")
        )
        for real_id in mapping["pseudonyms"]:
            assert real_id not in public_text
    assert scan_leaks(exporter.store, BATCH, second.version) == []


def test_repeated_export_with_changed_rules_does_not_merge_into_old_version(workspace, exporter):
    """规则变化后即使输出指纹相同，重复执行也不能返回旧规则版本。"""
    first = exporter.export_batch(BATCH, note="v1：基线")
    noop_rules = _rules_v1()
    noop_rules["visits"].append({"field": "visit_type", "action": "keep"})
    BatchStore(workspace).update_rules(BATCH, noop_rules, note="v2：文档化 visit_type 保留")

    second = exporter.export_batch(BATCH, note="v2：文档化 visit_type 保留")
    third = exporter.export_batch(BATCH, note="v2 再次导出仍指向新身份")
    assert third.reused is True
    assert third.version == second.version
    assert third.rules_version == 2
    assert third.version != first.version
