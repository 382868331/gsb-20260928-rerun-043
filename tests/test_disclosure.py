from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from crp.batch import BatchStore
from crp.disclosure import (
    ApplicationExistsError,
    ApplicationNotFoundError,
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
    record = preview["plans"]["as_requested"]["included_records"][0]
    # 同 record_id 的记录级对应因来源改名且无别名而缺少依据；不存在可确认的 record_key。
    assert "record_key" not in {link["basis"] for link in record["links"]}
    same_record = next(link for link in record["links"] if link["record_id"] == record["record_id"])
    assert same_record["basis"] == "unconfirmed"
    subject_summary = next(
        item for item in preview["plans"]["as_requested"]["new_disclosures"]
        if item["kind"] == "subject_links"
    )
    assert subject_summary["unconfirmed_prior"]
    # 受试者级关联（同一伪名）仍可确认；缺少依据的只是记录级对应。
    assert subject_summary["linkable_prior_deliveries"] == ["D001"]

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


# --------------------------------------------------------------------
# 第二轮：同接收者多份同时待审申请的联合预览
# --------------------------------------------------------------------

FORBID_LAB_DATE_WITH_DEPARTMENT = {
    "forbid_fields": [],
    "forbid_combinations": [{"fields": ["collected_at", "department"]}],
}


def test_two_pending_applications_are_jointly_previewed_for_same_recipient(setup):
    store, exporter, version, planner, trace = setup
    DisclosurePolicy(store, BATCH).revise(
        FORBID_LAB_DATE_WITH_DEPARTMENT, note="禁止检验日期+科室"
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-LABS",
        _request(version, trace, ["labs"], date_precision="day"), note="检验",
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-VISITS",
        _request(version, trace, ["visits"]), note="就诊",
    )
    labs_preview = planner.preview(BATCH, "REC-A", application_id="APP-LABS")
    visits_preview = planner.preview(BATCH, "REC-A", application_id="APP-VISITS")
    labs_blocked = labs_preview["plans"]["as_requested"]["blocked"]
    visits_blocked = visits_preview["plans"]["as_requested"]["blocked"]
    # 单看任一申请都没有本来源内的禁止字段组合；blocked 全部来自跨申请联合。
    assert {item["field"] for item in labs_blocked} == {"collected_at"}
    assert all(item.get("cross_union") for item in labs_blocked)
    assert {item["field"] for item in visits_blocked} == {"department"}
    assert all(item.get("cross_union") for item in visits_blocked)
    # 预览明确列出同时待审的另一份申请。
    assert [item["application_id"] for item in labs_preview["pending_applications"]] == ["APP-VISITS"]
    assert [item["application_id"] for item in visits_preview["pending_applications"]] == ["APP-LABS"]


def test_month_precision_labs_with_day_visits_does_not_form_exact_combo(setup):
    store, exporter, version, planner, trace = setup
    DisclosurePolicy(store, BATCH).revise(
        FORBID_LAB_DATE_WITH_DEPARTMENT, note="禁止检验日期+科室"
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-LABS",
        _request(version, trace, ["labs"], date_precision="month"), note="月精度检验",
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-VISITS",
        _request(version, trace, ["visits"]), note="就诊",
    )
    labs_preview = planner.preview(BATCH, "REC-A", application_id="APP-LABS")
    visits_preview = planner.preview(BATCH, "REC-A", application_id="APP-VISITS")
    # 检验只给到月：跨来源的精确日期+科室组合不成立。
    assert labs_preview["plans"]["as_requested"]["blocked"] == []
    assert visits_preview["plans"]["as_requested"]["blocked"] == []
    # 但联合预览仍列出两份申请合在一起会新增的受试者级组合（如实呈现，不参与拦截）。
    pending_kinds = {
        item["kind"] for item in visits_preview["plans"]["as_requested"]["new_disclosures"]
    }
    assert "pending_combination" in pending_kinds
    # 月精度检验材料可以先交付。
    result = planner.confirm(BATCH, "REC-A", labs_preview, "as_requested", note="先交月精度检验")
    material_dir = store.material_dir(BATCH, result["material_id"])
    assert all(len(row["collected_at"]) == 7 for row in read_csv(material_dir / "labs.csv"))


def test_confirming_one_pending_application_invalidates_the_other_preview(setup):
    store, exporter, version, planner, trace = setup
    DisclosurePolicy(store, BATCH).revise(
        FORBID_LAB_DATE_WITH_DEPARTMENT, note="禁止检验日期+科室"
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-LABS",
        _request(version, trace, ["labs"], date_precision="month"), note="月精度检验",
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-VISITS",
        _request(version, trace, ["visits"]), note="就诊",
    )
    stale = planner.preview(BATCH, "REC-A", application_id="APP-VISITS")
    labs_preview = planner.preview(BATCH, "REC-A", application_id="APP-LABS")
    planner.confirm(BATCH, "REC-A", labs_preview, "as_requested", note="先交检验")
    # 一份确认后，另一份的旧预览必须失效重审。
    with pytest.raises(StalePreviewError, match="过期"):
        planner.confirm(BATCH, "REC-A", stale, "as_requested")
    reviewed = planner.preview(BATCH, "REC-A", application_id="APP-VISITS")
    # 实际交付的检验是月精度，重审后精确组合仍不成立，可以交付。
    assert reviewed["plans"]["as_requested"]["blocked"] == []
    result = planner.confirm(BATCH, "REC-A", reviewed, "as_requested", note="再交就诊")
    assert result["delivery_id"] == "D002"


def test_pending_applications_are_isolated_between_recipients(setup):
    store, exporter, version, planner, trace = setup
    RecipientStore(store).register(BATCH, "REC-B", name="另一家机构")
    DisclosurePolicy(store, BATCH).revise(
        FORBID_LAB_DATE_WITH_DEPARTMENT, note="禁止检验日期+科室"
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-A-LABS", _request(version, trace, ["labs"]), note="A 检验",
    )
    planner.submit_application(
        BATCH, "REC-B", "APP-B-VISITS", _request(version, trace, ["visits"]), note="B 就诊",
    )
    preview_b = planner.preview(BATCH, "REC-B", application_id="APP-B-VISITS")
    # REC-B 看不到 REC-A 的待审申请，历史与待审都隔离。
    assert preview_b["pending_applications"] == []
    assert preview_b["plans"]["as_requested"]["blocked"] == []


def test_confirmation_order_cannot_bypass_combination_limit(setup):
    store, exporter, version, planner, trace = setup
    DisclosurePolicy(store, BATCH).revise(
        FORBID_LAB_DATE_WITH_DEPARTMENT, note="禁止检验日期+科室"
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-LABS", _request(version, trace, ["labs"]), note="检验",
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-VISITS", _request(version, trace, ["visits"]), note="就诊",
    )
    # 无论先确认哪一份，as_requested 都因联合组合被拦截，不能靠确认顺序绕过。
    for app_id in ("APP-LABS", "APP-VISITS"):
        preview = planner.preview(BATCH, "REC-A", application_id=app_id)
        with pytest.raises(DisclosurePolicyError, match="forbid_combination"):
            planner.confirm(BATCH, "REC-A", preview, "as_requested")
    # 降到月精度后组合不成立，可以确认。
    visits_preview = planner.preview(BATCH, "REC-A", application_id="APP-VISITS")
    result = planner.confirm(
        BATCH, "REC-A", visits_preview, "reduce_precision", note="就诊降到月",
    )
    assert result["delivery_id"] == "D001"
    # 先交付一份后，另一份旧预览同样失效，需要按已交付的月精度重新核对。
    labs_preview = planner.preview(BATCH, "REC-A", application_id="APP-LABS")
    assert labs_preview["plans"]["as_requested"]["blocked"] == []
    result = planner.confirm(BATCH, "REC-A", labs_preview, "as_requested", note="再交检验")
    assert result["delivery_id"] == "D002"


def test_upgrading_to_day_precision_creates_combo_after_month_delivery(setup):
    store, exporter, version, planner, trace = setup
    DisclosurePolicy(store, BATCH).revise(
        FORBID_LAB_DATE_WITH_DEPARTMENT, note="禁止检验日期+科室"
    )
    planner.submit_application(
        BATCH, "REC-A", "APP-LABS-M",
        _request(version, trace, ["labs"], date_precision="month"), note="月精度检验",
    )
    month_preview = planner.preview(BATCH, "REC-A", application_id="APP-LABS-M")
    planner.confirm(BATCH, "REC-A", month_preview, "as_requested", note="月精度检验交付")
    planner.submit_application(
        BATCH, "REC-A", "APP-VISITS", _request(version, trace, ["visits"]), note="就诊",
    )
    visits_preview = planner.preview(BATCH, "REC-A", application_id="APP-VISITS")
    assert visits_preview["plans"]["as_requested"]["blocked"] == []
    planner.confirm(BATCH, "REC-A", visits_preview, "as_requested", note="月精度组合下就诊")
    # 后续申请把同一份检验提升到日精度：与已交付的就诊资料形成新的精确组合。
    planner.submit_application(
        BATCH, "REC-A", "APP-LABS-D",
        _request(version, trace, ["labs"], date_precision="day"), note="日精度检验",
    )
    day_preview = planner.preview(BATCH, "REC-A", application_id="APP-LABS-D")
    blocked = day_preview["plans"]["as_requested"]["blocked"]
    assert {item["field"] for item in blocked} == {"collected_at"}
    with pytest.raises(DisclosurePolicyError, match="forbid_combination"):
        planner.confirm(BATCH, "REC-A", day_preview, "as_requested")


def test_cancel_application_is_not_registered(setup):
    store, exporter, version, planner, trace = setup
    planner.submit_application(
        BATCH, "REC-A", "APP-LABS", _request(version, trace, ["labs"]), note="检验",
    )
    preview = planner.preview(BATCH, "REC-A", application_id="APP-LABS")
    result = planner.confirm(BATCH, "REC-A", preview, "cancel")
    assert result["cancelled"] is True
    assert result["application_id"] == "APP-LABS"
    # 取消不登记：待审清单、交付登记、材料目录都没有痕迹。
    assert planner.applications_pending(BATCH, "REC-A") == []
    assert DeliveryRegistry(store).deliveries(BATCH, "REC-A") == []
    materials_root = store.root / "disclosure" / BATCH / "materials"
    assert not materials_root.exists() or not list(materials_root.iterdir())
    with pytest.raises(ApplicationNotFoundError):
        planner.cancel_application(BATCH, "REC-A", "APP-LABS")


def test_pending_application_persists_and_can_be_reopened_after_restart(setup):
    store, exporter, version, planner, trace = setup
    planner.submit_application(
        BATCH, "REC-A", "APP-LABS", _request(version, trace, ["labs"]), note="检验",
    )
    # 用全新的 planner 实例重开：待审申请从磁盘恢复。
    reopened = DisclosurePlanner(store)
    pending = reopened.applications_pending(BATCH, "REC-A")
    assert [item["application_id"] for item in pending] == ["APP-LABS"]
    preview = reopened.preview(BATCH, "REC-A", application_id="APP-LABS")
    result = reopened.confirm(BATCH, "REC-A", preview, "as_requested", note="重开后确认")
    assert result["delivery_id"] == "D001"
    # 已确认的申请留痕为 confirmed，不再出现在待审清单。
    assert reopened.applications_pending(BATCH, "REC-A") == []
    with pytest.raises(ApplicationExistsError):
        reopened.submit_application(
            BATCH, "REC-A", "APP-LABS", _request(version, trace, ["labs"]), note="重复",
        )
