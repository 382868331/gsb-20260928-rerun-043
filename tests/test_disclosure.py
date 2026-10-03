from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from crp.batch import BatchStore
from crp.disclosure import (
    DeliveryRegistry,
    DisclosurePlanner,
    DisclosurePolicy,
    DisclosurePolicyError,
    MaterialBuilder,
    RecipientStore,
    StalePreviewError,
    scan_material_leaks,
)
from crp.exporter import Exporter
from crp.paths import Store
from crp.util import read_csv, read_json

ROOT = Path(__file__).resolve().parents[1]
BATCH = "STUDY-001"


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    shutil.copytree(ROOT / "data" / "raw", tmp_path / "raw")
    return Store.create(tmp_path)


@pytest.fixture()
def setup(store):
    BatchStore(store).create(read_json(ROOT / "configs" / "study001.json"))
    exporter = Exporter(store)
    version = exporter.export_batch(BATCH, note="v1 全量基线").version
    RecipientStore(store).register(BATCH, "REC-A", name="某医院科研科")
    planner = DisclosurePlanner(store)
    trace = read_csv(store.version_dir(BATCH, version) / "rule_trace.csv")
    return store, exporter, version, planner, trace


def _request(version: int, trace, tables, **extra):
    request = {
        "version": version,
        "records": [
            {"table": row["table"], "record_id": row["record_id"]}
            for row in trace if row["table"] in tables
        ],
    }
    request.update(extra)
    return request


def _record(plan, table, index=0):
    records = [r for r in plan["included_records"] if r["table"] == table]
    return records[index]


def test_preview_links_second_delivery_to_first_and_lists_new_combos(setup):
    store, exporter, version, planner, trace = setup
    first = planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"]))
    result = planner.confirm(BATCH, "REC-A", first, "as_requested", note="第一次：检验")
    assert result["delivery_id"] == "D001"

    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["visits"]))
    plan = preview["plans"]["as_requested"]
    record = _record(plan, "visits", 0)
    # 同一受试者跨表稳定伪名：可确认的受试者级关联指向第一次交付。
    assert {link["basis"] for link in record["links"]} == {"subject"}
    assert record["links"][0]["delivery_id"] == "D001"
    assert record["links"][0]["source_name"] == "labs"
    # 日期/科室/主诉等是新增可关联字段；伪名与已见过的 visit_id 不是新增。
    fields = {item["field"]: item for item in record["fields"]}
    assert fields["visit_date"]["newly_linkable"] is True
    assert fields["department"]["newly_linkable"] is True
    assert fields["subject_id"]["newly_linkable"] is False
    combos = [item for item in plan["new_disclosures"] if item["kind"] == "new_combination"]
    assert combos and combos[0]["basis"] == "subject"
    assert combos[0]["prior"]["delivery_id"] == "D001"


def test_same_record_reappearing_is_record_key_link_even_across_new_export(setup):
    store, exporter, version, planner, trace = setup
    planner.confirm(
        BATCH, "REC-A",
        planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"])),
        "as_requested", note="第一次：检验",
    )
    # 新导出版本中同一批记录再次出现（规则修订导致的新执行）。
    BatchStore(store).update_rules(
        BATCH, read_json(ROOT / "configs" / "study001_rules_v2.json"),
        note="v2", scope={"sources": ["labs"]},
    )
    v2 = exporter.export_batch(BATCH, note="v2 执行").version
    trace2 = read_csv(store.version_dir(BATCH, v2) / "rule_trace.csv")
    preview = planner.preview(BATCH, "REC-A", _request(v2, trace2, ["labs"]))
    record = preview["plans"]["as_requested"]["included_records"][0]
    assert record["links"][0]["basis"] == "record_key"


def test_source_rename_without_alias_is_unconfirmed_and_not_guessed(setup):
    store, exporter, version, planner, trace = setup
    planner.confirm(
        BATCH, "REC-A",
        planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"])),
        "as_requested", note="d1",
    )
    request = _request(version, trace, ["labs"], source_names={"labs": "laboratory_results"})
    preview = planner.preview(BATCH, "REC-A", request)
    records = preview["plans"]["as_requested"]["included_records"]
    # 所有记录都不存在可确认的 record_key（来源改名且无别名）。
    for record in records:
        assert "record_key" not in {link["basis"] for link in record["links"]}
        same_record = next(link for link in record["links"] if link["record_id"] == record["record_id"])
        assert same_record["basis"] == "unconfirmed"
    subject_summaries = [
        item for item in preview["plans"]["as_requested"]["new_disclosures"]
        if item["kind"] == "subject_links"
    ]
    # 同受试者在既有材料里还有其他记录时，受试者级关联仍可确认（如 PT001 有两条 LDL）。
    multi = next(item for item in subject_summaries if len(item["records"]) >= 2 or item["linkable_prior_deliveries"])
    assert multi["unconfirmed_prior"]
    assert multi["linkable_prior_deliveries"] == ["D001"]
    # 只有一条既往记录的受试者，记录级对应缺少依据时不得靠猜测补出关联。
    single = next(item for item in subject_summaries if not item["linkable_prior_deliveries"])
    assert single["unconfirmed_prior"] and not single["linkable_prior_deliveries"]

    # 提供显式来源别名后，记录级对应才被确认。
    request = _request(
        version, trace, ["labs"],
        source_names={"labs": "laboratory_results"},
        source_aliases={"labs": "labs"},
    )
    preview2 = planner.preview(BATCH, "REC-A", request)
    record2 = preview2["plans"]["as_requested"]["included_records"][0]
    assert record2["links"][0]["basis"] == "record_key"


def test_reduce_precision_plan_truncates_dates_and_reports_residual_links(setup):
    store, exporter, version, planner, trace = setup
    planner.confirm(
        BATCH, "REC-A",
        planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"])),
        "as_requested", note="d1",
    )
    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["visits"]))
    reduced = preview["plans"]["reduce_precision"]
    spec = reduced["material_spec"]
    assert spec["date_precision"] == "month"
    result = planner.confirm(BATCH, "REC-A", preview, "reduce_precision", note="降到月")
    material_dir = store.material_dir(BATCH, result["material_id"])
    visits = read_csv(material_dir / "visits.csv")
    assert all(len(row["visit_date"]) == 7 for row in visits)


def test_finer_date_request_is_flagged_as_precision_upgrade(setup):
    store, exporter, version, planner, trace = setup
    # 第一次只给到月精度。
    first = planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"]))
    planner.confirm(BATCH, "REC-A", first, "reduce_precision", note="月精度")
    # 之后申请同一批记录的日精度。
    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"]))
    record = preview["plans"]["as_requested"]["included_records"][0]
    collected = next(item for item in record["fields"] if item["field"] == "collected_at")
    assert collected["newly_linkable"] is True
    assert collected["precision_upgrade_from"] == "month"
    assert collected["first_delivered_by"] == "D001"
    new_field = next(
        item for item in preview["plans"]["as_requested"]["new_disclosures"]
        if item["kind"] == "new_field" and item["field"] == "collected_at"
    )
    assert new_field["precision_upgrade_from"] == "month"
    # 降低精度方案不会把更细日期重新公开。
    reduced_field = next(
        item for item in preview["plans"]["reduce_precision"]["included_records"][0]["fields"]
        if item["field"] == "collected_at"
    )
    assert reduced_field["newly_linkable"] is False


def test_cancel_plan_creates_no_material(setup):
    store, exporter, version, planner, trace = setup
    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["visits"]))
    result = planner.confirm(BATCH, "REC-A", preview, "cancel")
    assert result["cancelled"] is True
    assert DeliveryRegistry(store).deliveries(BATCH, "REC-A") == []


def test_policy_can_forbid_new_combination_for_future_only(setup):
    store, exporter, version, planner, trace = setup
    planner.confirm(
        BATCH, "REC-A",
        planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"])),
        "as_requested", note="d1",
    )
    DisclosurePolicy(store, BATCH).revise(
        {"forbid_fields": [], "forbid_combinations": [
            {"fields": ["visit_date", "department"]}
        ]},
        note="禁止日期+科室组合",
    )
    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["visits"]))
    with pytest.raises(DisclosurePolicyError, match="forbid_combination"):
        planner.confirm(BATCH, "REC-A", preview, "as_requested")
    allowed = preview["plans"]["allow_only"]
    assert {item["kind"] for item in allowed["blocked"]} >= {"forbid_combination"}
    # 允许方案剔除触发组合的字段后可以交付。
    result = planner.confirm(BATCH, "REC-A", preview, "allow_only", note="去掉科室")
    assert result["delivery_id"] == "D002"
    material_dir = store.material_dir(BATCH, result["material_id"])
    assert "department" not in read_csv(material_dir / "visits.csv")[0]
    # 历史交付 D001 不被政策修订改写。
    deliveries = DeliveryRegistry(store).deliveries(BATCH, "REC-A")
    assert deliveries[0]["delivery_id"] == "D001"


def test_narrowed_authorization_only_affects_later_deliveries(setup):
    store, exporter, version, planner, trace = setup
    first_preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"]))
    planner.confirm(BATCH, "REC-A", first_preview, "as_requested", note="d1")
    # 授权缩小为只允许 labs 中的一条检验记录。
    labs_trace = [row for row in trace if row["table"] == "labs"]
    allowed_key = labs_trace[0]["record_id"].split(":", 1)[1]
    RecipientStore(store).narrow_authorization(
        BATCH, "REC-A",
        {"records": [{"table": "labs", "record_id": allowed_key}]},
        note="缩小到一条检验",
    )
    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["labs", "visits"]))
    plan = preview["plans"]["allow_only"]
    assert len(plan["included_records"]) == 1
    assert all(item["kind"] == "outside_authorization" for item in plan["blocked"])
    # 历史交付仍有完整记录。
    first_delivery = DeliveryRegistry(store).deliveries(BATCH, "REC-A")[0]
    material_dir = store.material_dir(BATCH, first_delivery["material_id"])
    assert len(read_csv(material_dir / "labs.csv")) == len(labs_trace)


def test_stale_preview_is_rejected_after_new_delivery(setup):
    store, exporter, version, planner, trace = setup
    stale = planner.preview(BATCH, "REC-A", _request(version, trace, ["visits"]))
    # 预览生成后，另一次交付落地（既有交付范围增加）。
    planner.confirm(
        BATCH, "REC-A",
        planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"])),
        "as_requested", note="夹在中间的交付",
    )
    with pytest.raises(StalePreviewError, match="过期"):
        planner.confirm(BATCH, "REC-A", stale, "as_requested")


def test_duplicate_material_is_not_double_counted_on_retry(setup):
    store, exporter, version, planner, trace = setup
    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"]))
    first = planner.confirm(BATCH, "REC-A", preview, "as_requested", note="首次")
    second = planner.confirm(BATCH, "REC-A", preview, "as_requested", note="网络重试")
    assert second["material_id"] == first["material_id"]
    assert second["delivery_reused"] is True
    registry = DeliveryRegistry(store).load(BATCH, "REC-A")
    assert len(registry["deliveries"]) == 1
    assert registry["deliveries"][0]["attempts"] == 2
    material_dirs = list((store.root / "disclosure" / BATCH / "materials").iterdir())
    assert len(material_dirs) == 1


def test_audit_note_stays_internal_and_raw_values_never_enter_material(setup):
    store, exporter, version, planner, trace = setup
    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["demographics", "labs"]))
    result = planner.confirm(
        BATCH, "REC-A", preview, "as_requested",
        note="交付", audit_note="内部核对：对应真实编号 PT001，身份证 110101199003071234",
    )
    material_dir = store.material_dir(BATCH, result["material_id"])
    material_text = " ".join(
        path.read_text(encoding="utf-8") for path in material_dir.rglob("*") if path.is_file()
    )
    assert "PT001" not in material_text
    assert "110101199003071234" not in material_text
    assert scan_material_leaks(store, BATCH, result["material_id"]) == []
    # 审计说明只存在内部登记中。
    registry = DeliveryRegistry(store).load(BATCH, "REC-A")
    assert "PT001" in registry["deliveries"][0]["audit_note"]


def test_preview_is_bound_to_recipient_and_identity(setup):
    store, exporter, version, planner, trace = setup
    RecipientStore(store).register(BATCH, "REC-B", name="另一家机构")
    preview = planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"]))
    with pytest.raises(ValueError, match="不一致"):
        planner.confirm(BATCH, "REC-B", preview, "as_requested")
