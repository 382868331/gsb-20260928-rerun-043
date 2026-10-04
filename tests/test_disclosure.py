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
    PendingApplicationStore,
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
        if item["kind"] == "subject_links" and item["pseudonym"] == record["pseudonym"]
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


def test_pending_joint_preview_reopen_and_stale_after_peer_confirm(setup):
    store, exporter, version, planner, trace = setup
    # 两份待审申请落盘：检验按月精度、就诊按默认日精度。
    planner.preview(BATCH, "REC-A", _request(
        version, trace, ["labs"], application_id="APP-1", date_precision="month",
    ), save=True)
    planner.preview(BATCH, "REC-A", _request(
        version, trace, ["visits"], application_id="APP-2",
    ), save=True)
    # 关闭重开：待审申请从磁盘恢复，每份都显式携带实际日期精度。
    planner = DisclosurePlanner(store)
    entries = PendingApplicationStore(store).list(BATCH, "REC-A")
    assert {item["application_id"]: item["date_precision"] for item in entries} == {
        "APP-1": "month", "APP-2": "day",
    }
    # 联合预览：同伴申请按实际精度进入核对，读取 date_precision 不再缺键崩溃。
    preview2 = planner.preview(BATCH, "REC-A", _request(
        version, trace, ["visits"], application_id="APP-2",
    ), save=True)
    assert [
        (item["application_id"], item["date_precision"])
        for item in preview2["peer_pending"]
    ] == [("APP-1", "month")]
    # 确认 APP-1：月精度检验材料落地为 D001。
    first = planner.preview(BATCH, "REC-A", _request(
        version, trace, ["labs"], application_id="APP-1", date_precision="month",
    ), save=True)
    result1 = planner.confirm(BATCH, "REC-A", first, "as_requested", note="检验（月）")
    assert result1["delivery_id"] == "D001"
    material_dir = store.material_dir(BATCH, result1["material_id"])
    assert all(len(row["collected_at"]) == 7 for row in read_csv(material_dir / "labs.csv"))
    # APP-2 的旧预览因同接收方待审清单与既有交付变化而过期，必须重审。
    with pytest.raises(StalePreviewError, match="过期"):
        planner.confirm(BATCH, "REC-A", preview2, "as_requested")
    # 重审后确认：APP-1 此后作为既有交付计入联合核对。
    second = planner.preview(BATCH, "REC-A", _request(
        version, trace, ["visits"], application_id="APP-2",
    ), save=True)
    assert second["peer_pending"] == []
    assert [item["delivery_id"] for item in second["prior_deliveries"]] == ["D001"]
    result2 = planner.confirm(BATCH, "REC-A", second, "as_requested", note="就诊")
    assert result2["delivery_id"] == "D002"
    assert PendingApplicationStore(store).list(BATCH, "REC-A") == []


def test_precision_upgrade_and_combination_not_bypassed_by_confirm_order(setup):
    store, exporter, version, planner, trace = setup
    # 检验先按月精度交付。
    planner.confirm(
        BATCH, "REC-A",
        planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"], date_precision="month")),
        "as_requested", note="检验（月）",
    )
    # 检验提升至日精度重审：如实标注较既往实际交付精度（月）的升级。
    upgrade = planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"], date_precision="day"))
    fields = {item["field"]: item for item in _record(upgrade["plans"]["as_requested"], "labs")["fields"]}
    assert fields["collected_at"]["precision_upgrade_from"] == "month"
    assert fields["collected_at"]["newly_linkable"] is True
    # 政策禁止「检验日期 + 就诊日期」组合，只约束今后的交付。
    DisclosurePolicy(store, BATCH).revise(
        {"forbid_fields": [], "forbid_combinations": [
            {"fields": ["collected_at", "visit_date"]}
        ]},
        note="禁止检验日期+就诊日期组合",
    )
    # 两份待审申请：检验日精度升级 + 就诊资料。
    planner.preview(BATCH, "REC-A", _request(
        version, trace, ["labs"], application_id="APP-U", date_precision="day",
    ), save=True)
    planner.preview(BATCH, "REC-A", _request(
        version, trace, ["visits"], application_id="APP-V",
    ), save=True)
    # 无论先审哪一份，联合判定都拦下组合：改变确认顺序无法绕过。
    preview_u = planner.preview(BATCH, "REC-A", _request(
        version, trace, ["labs"], application_id="APP-U", date_precision="day",
    ), save=True)
    combo_u = [b for b in preview_u["plans"]["as_requested"]["blocked"]
               if b["kind"] == "forbid_combination"]
    assert combo_u and {app for b in combo_u for app in b["peer_applications"]} == {"APP-V"}
    preview_v = planner.preview(BATCH, "REC-A", _request(
        version, trace, ["visits"], application_id="APP-V",
    ), save=True)
    assert any(b["kind"] == "forbid_combination"
               for b in preview_v["plans"]["as_requested"]["blocked"])
    with pytest.raises(DisclosurePolicyError, match="forbid_combination"):
        planner.confirm(BATCH, "REC-A", preview_v, "as_requested")
    # 先确认检验（剔除检验日期后交付），就诊申请依旧撞组合：顺序换不掉判定。
    result_u = planner.confirm(BATCH, "REC-A", preview_u, "allow_only", note="去掉检验日期")
    material_dir = store.material_dir(BATCH, result_u["material_id"])
    assert "collected_at" not in read_csv(material_dir / "labs.csv")[0]
    preview_v2 = planner.preview(BATCH, "REC-A", _request(
        version, trace, ["visits"], application_id="APP-V",
    ), save=True)
    assert any(b["kind"] == "forbid_combination"
               for b in preview_v2["plans"]["as_requested"]["blocked"])
    with pytest.raises(DisclosurePolicyError, match="forbid_combination"):
        planner.confirm(BATCH, "REC-A", preview_v2, "as_requested")
    # 月精度下两日期仍可关联，组合依旧成立；只有剔除触发字段才能交付。
    assert any(b["kind"] == "forbid_combination"
               for b in preview_v2["plans"]["reduce_precision"]["blocked"])
    result_v = planner.confirm(BATCH, "REC-A", preview_v2, "allow_only", note="去掉就诊日期")
    material_dir = store.material_dir(BATCH, result_v["material_id"])
    assert "visit_date" not in read_csv(material_dir / "visits.csv")[0]


def test_cancel_leaves_no_registration_and_recipients_are_isolated(setup):
    store, exporter, version, planner, trace = setup
    RecipientStore(store).register(BATCH, "REC-B", name="另一家机构")
    planner.preview(BATCH, "REC-A", _request(
        version, trace, ["labs"], application_id="APP-1",
    ), save=True)
    # 不同接收方的待审申请互不可见。
    planner.preview(BATCH, "REC-B", _request(
        version, trace, ["visits"], application_id="APP-9",
    ), save=True)
    preview_b = planner.preview(BATCH, "REC-B", _request(
        version, trace, ["medications"], application_id="APP-10",
    ), save=True)
    assert [item["application_id"] for item in preview_b["peer_pending"]] == ["APP-9"]
    assert preview_b["prior_deliveries"] == []
    # 取消不登记：不形成材料、不留交付，待审申请直接移除。
    preview_a = planner.preview(BATCH, "REC-A", _request(
        version, trace, ["labs"], application_id="APP-1",
    ), save=True)
    result = planner.confirm(BATCH, "REC-A", preview_a, "cancel")
    assert result["cancelled"] is True
    assert DeliveryRegistry(store).deliveries(BATCH, "REC-A") == []
    assert PendingApplicationStore(store).list(BATCH, "REC-A") == []
    # REC-B 的待审申请不受 REC-A 取消影响。
    assert {
        item["application_id"]
        for item in PendingApplicationStore(store).list(BATCH, "REC-B")
    } == {"APP-9", "APP-10"}
    # REC-A 确认交付后，REC-B 的既有交付历史仍为空，严格隔离。
    planner.confirm(
        BATCH, "REC-A",
        planner.preview(BATCH, "REC-A", _request(version, trace, ["labs"])),
        "as_requested", note="d1",
    )
    assert DeliveryRegistry(store).deliveries(BATCH, "REC-B") == []
    preview_b2 = planner.preview(BATCH, "REC-B", _request(
        version, trace, ["medications"], application_id="APP-10",
    ), save=True)
    assert preview_b2["prior_deliveries"] == []
