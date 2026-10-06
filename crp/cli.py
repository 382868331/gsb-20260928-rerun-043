"""命令行入口：python -m crp ..."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from crp.audit import cross_table_consistency, scan_leaks
from crp.batch import BatchStore
from crp.disclosure import (
    DeliveryRegistry,
    DisclosurePlanner,
    DisclosurePolicy,
    PendingApplicationNotFoundError,
    PendingApplicationStore,
    RecipientStore,
    StalePreviewError,
)
from crp.exporter import Exporter
from crp.paths import Store
from crp.util import read_json


def _json_arg(file_arg: str | None, inline_arg: str | None) -> dict:
    if file_arg:
        return read_json(Path(file_arg))
    return json.loads(inline_arg)


def _store(args: argparse.Namespace) -> Store:
    return Store.create(Path(args.data_root))


def cmd_init_batch(args: argparse.Namespace) -> None:
    config = read_json(Path(args.config))
    batch = BatchStore(_store(args)).create(config, note=args.note)
    print(f"已创建批次 {batch.batch_id}（字段规则 v{batch.rules_version}）")


def cmd_update_rules(args: argparse.Namespace) -> None:
    new_rules = read_json(Path(args.rules))
    scope = None
    if args.scope:
        scope = json.loads(Path(args.scope).read_text(encoding="utf-8"))
    elif args.scope_json:
        scope = json.loads(args.scope_json)
    batch = BatchStore(_store(args)).update_rules(args.batch_id, new_rules, note=args.note, scope=scope)
    print(f"批次 {batch.batch_id} 字段规则已更新至 v{batch.rules_version}（旧版本说明与适用范围保留）")


def cmd_preview_scope(args: argparse.Namespace) -> None:
    if not args.scope and not args.scope_json:
        raise SystemExit("必须通过 --scope 或 --scope-json 提供适用范围")
    scope = json.loads(Path(args.scope).read_text(encoding="utf-8")) if args.scope else json.loads(args.scope_json)
    preview = Exporter(_store(args)).preview_scope(args.batch_id, scope)
    print(f"命中 {len(preview.included)} 条，范围外 {len(preview.excluded)} 条")
    for item in preview.included:
        print(f"  命中 {item['table']}:{item['row_number']} 受试者 {item['subject_id']}")


def cmd_export(args: argparse.Namespace) -> None:
    result = Exporter(_store(args)).export_batch(args.batch_id, note=args.note)
    action = "复用既有" if result.reused else "生成新"
    print(f"{action}导出版本 v{result.version:03d}：{result.version_dir}")
    print(f"依据字段规则 v{result.rules_version}；版本说明：{result.note}")
    if not result.reused and result.content_reused_from is not None:
        print(
            f"规则/输入已变化，本次为独立执行版本；最终文件字节与 v{result.content_reused_from:03d} 一致，"
            "已在 manifest 中记录内容来源"
        )


def cmd_verify(args: argparse.Namespace) -> None:
    store = _store(args)
    index = Exporter(store)._load_index(args.batch_id)
    version = args.version if args.version is not None else int(index["latest"])
    findings = scan_leaks(store, args.batch_id, version)
    linked = cross_table_consistency(store, args.batch_id, version)
    if findings:
        for item in findings:
            print(f"[泄露] {item}")
        raise SystemExit(1)
    print(f"v{version:03d} 泄露核对通过；跨表关联受试者 {len(linked)} 人")
    for sid, places in linked.items():
        print(f"  {sid} -> {', '.join(places)}")


def cmd_versions(args: argparse.Namespace) -> None:
    store = _store(args)
    index = Exporter(store)._load_index(args.batch_id)
    if not index["versions"]:
        print("暂无导出版本")
        return
    for entry in index["versions"]:
        print(f"v{int(entry['version']):03d} 规则v{entry['rules_version']} {entry['created_at']} {entry['note']}")


def cmd_compare(args: argparse.Namespace) -> None:
    comparison = Exporter(_store(args)).compare_versions(
        args.batch_id, args.from_version, args.to_version
    )
    print(f"比较 v{args.from_version:03d} -> v{args.to_version:03d}")
    labels = (
        ("规则变化", comparison.rules_changed),
        ("适用范围变化", comparison.scope_changed),
        ("输入数据变化", comparison.source_changed),
        ("最终内容变化", comparison.output_changed),
    )
    for label, changed in labels:
        mark = "是" if changed else "否"
        print(f"  {label}: {mark}")
    print(
        f"  规则版本: v{comparison.rules_version_from} -> v{comparison.rules_version_to}"
    )
    print("  配置相同: {}".format("是" if comparison.rules_config_equal else "否"))
    print("  公开输出相同: {}".format("是" if comparison.output_equal else "否"))
    print("  属于同一次执行: {}".format("是" if comparison.same_execution else "否"))
    if comparison.added_files:
        print(f"  新增文件: {', '.join(comparison.added_files)}")
    if comparison.removed_files:
        print(f"  删除文件: {', '.join(comparison.removed_files)}")
    if comparison.changed_files:
        print(f"  内容变化文件: {', '.join(comparison.changed_files)}")


def cmd_rule_trail(args: argparse.Namespace) -> None:
    trail = Exporter(_store(args)).rule_trail(args.batch_id)
    if not trail:
        print("暂无执行记录")
        return
    print(f"批次 {args.batch_id} 沿规则修订顺序的执行记录：")
    for item in trail:
        tags: list[str] = []
        if item["same_execution_as_previous"]:
            tags.append("同一次执行重跑")
        elif item["rules_config_equal_previous"]:
            tags.append("规则配置退回/重复")
        if item["output_equal_previous"] and not item["same_execution_as_previous"]:
            tags.append("公开输出与上一版相同")
        if item["content_reused_from"] is not None:
            tags.append(f"内容复用自 v{item['content_reused_from']:03d}")
        tag_text = f"（{'，'.join(tags)}）" if tags else ""
        print(
            f"  v{item['version']:03d} 依据规则修订 v{item['rules_version']}：{item['note']}{tag_text}"
        )


def cmd_recipient_register(args: argparse.Namespace) -> None:
    authorization = _json_arg(args.scope, args.scope_json) if (args.scope or args.scope_json) else None
    recipient = RecipientStore(_store(args)).register(
        args.batch_id, args.recipient_id, name=args.name,
        authorization=authorization, note=args.note,
    )
    print(f"已登记接收者 {recipient.recipient_id}（{recipient.name}），授权修订 v{recipient.authorization_revision}")


def cmd_recipient_narrow(args: argparse.Namespace) -> None:
    if not args.scope and not args.scope_json:
        raise SystemExit("必须通过 --scope 或 --scope-json 提供缩小后的授权范围")
    scope = _json_arg(args.scope, args.scope_json)
    recipient = RecipientStore(_store(args)).narrow_authorization(
        args.batch_id, args.recipient_id, scope, note=args.note,
    )
    print(
        f"接收者 {recipient.recipient_id} 授权已追加修订 v{recipient.authorization_revision}；"
        "历史授权与已交付记录保持不变"
    )


def cmd_policy_revise(args: argparse.Namespace) -> None:
    if not args.rules and not args.rules_json:
        raise SystemExit("必须通过 --rules 或 --rules-json 提供披露政策")
    rules = _json_arg(args.rules, args.rules_json)
    revision = DisclosurePolicy(_store(args), args.batch_id).revise(rules, note=args.note)
    print(f"披露政策已修订至 v{revision['revision']}：{args.note}（仅影响此后新交付）")


def cmd_disclosure_preview(args: argparse.Namespace) -> None:
    if not args.request and not args.request_json:
        raise SystemExit("必须通过 --request 或 --request-json 提供本次资料申请")
    request = _json_arg(args.request, args.request_json)
    if args.application_id:
        request = dict(request)
        request["application_id"] = args.application_id
    preview = DisclosurePlanner(_store(args)).preview(
        args.batch_id, args.recipient_id, request, save=args.save,
    )
    if args.output:
        Path(args.output).write_text(json.dumps(preview, ensure_ascii=False, indent=2) + "\n",
                                      encoding="utf-8")
    as_requested_spec = preview["plans"]["as_requested"].get("material_spec")
    requested_precision = preview.get(
        "requested_date_precision",
        as_requested_spec.get("date_precision") if as_requested_spec else "-",
    )
    print(
        f"接收者 {args.recipient_id} 联合披露预览：绑定导出版本 v{preview['request_version']}，"
        f"授权 v{preview['authorization_revision']}，政策 v{preview['policy_revision']}，"
        f"本次申请公开日期精度 {requested_precision}，"
        f"既有交付 {len(preview['prior_deliveries'])} 次，"
        f"同接收方待审申请 {len(preview['peer_pending'])} 份"
    )
    if preview["application_id"]:
        print(f"  申请号 {preview['application_id']}：已保存为待审申请，确认或取消前一直有效")
    for name, plan in preview["plans"].items():
        print(f"  [{name}] {plan['description']}")
        print(f"    交付 {len(plan['included_records'])} 条；新增可关联内容 {len(plan['new_disclosures'])} 项；"
              f"受限/阻止 {len(plan['blocked'])} 项")
        for item in plan["blocked"]:
            detail = item.get("field") or item.get("record_id", "")
            print(f"      阻止: {item['kind']} {item.get('table', '')}:{detail}")
    if args.output:
        print(f"预览快照已写入 {args.output}（确认时必须回传同一份，过期需重新核对）")


def cmd_disclosure_confirm(args: argparse.Namespace) -> None:
    preview = read_json(Path(args.preview))
    try:
        result = DisclosurePlanner(_store(args)).confirm(
            args.batch_id, args.recipient_id, preview, args.plan,
            note=args.note, audit_note=args.audit_note or "",
        )
    except StalePreviewError as exc:
        raise SystemExit(str(exc))
    except PendingApplicationNotFoundError as exc:
        raise SystemExit(f"待审申请已处理或不存在，必须重新预览后再确认：{exc}")
    if result["cancelled"]:
        print("已取消本次交付：未形成任何对外材料，未登记交付，待审申请已移除")
        return
    reused = "（同一份对外材料，未重复计入披露）" if result["delivery_reused"] else ""
    print(
        f"已登记交付 {result['delivery_id']}：材料 {result['material_id']}{reused}；"
        f"新增可关联内容 {len(result['new_disclosures'])} 项"
    )


def cmd_pending_list(args: argparse.Namespace) -> None:
    store = _store(args)
    entries = PendingApplicationStore(store).list(args.batch_id, args.recipient_id)
    if not entries:
        print(f"接收者 {args.recipient_id} 暂无待审申请")
        return
    print(f"接收者 {args.recipient_id} 的待审申请（{len(entries)} 份，相互联合核对）：")
    for entry in entries:
        records = entry["request"].get("records", [])
        tables = sorted({item["table"] for item in records})
        print(
            f"  {entry['application_id']} v{entry['request'].get('version')} "
            f"日期精度 {PendingApplicationStore.entry_date_precision(entry)} "
            f"来源 {','.join(tables) or '-'} 记录 {len(records)} 条 {entry.get('note', '')}"
        )


def cmd_deliveries(args: argparse.Namespace) -> None:
    from crp.disclosure import DeliveryRegistry
    deliveries = DeliveryRegistry(_store(args)).deliveries(args.batch_id, args.recipient_id)
    if not deliveries:
        print(f"接收者 {args.recipient_id} 暂无交付记录")
        return
    print(f"接收者 {args.recipient_id} 的既有交付：")
    for item in deliveries:
        print(
            f"  {item['delivery_id']} 材料 {item['material_id']} 时间 {item['created_at']} "
            f"授权v{item['authorization_revision']} 政策v{item['policy_revision']} "
            f"公开日期精度 {item.get('public_date_precision', item.get('spec', {}).get('date_precision', 'day'))} "
            f"{item['note']}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="crp", description="临床研究数据平台：虚构资料去标识导出")
    parser.add_argument("--data-root", default="data", help="数据根目录（默认 ./data）")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init-batch", help="按 JSON 配置创建研究批次")
    p.add_argument("--config", required=True)
    p.add_argument("--note", default="初始字段规则")
    p.set_defaults(func=cmd_init_batch)
    p = sub.add_parser("update-rules", help="更新字段规则并留痕")
    p.add_argument("batch_id")
    p.add_argument("--rules", required=True, help="完整替换用的规则 JSON")
    p.add_argument("--note", required=True)
    p.add_argument("--scope", help="适用范围 JSON 文件")
    p.add_argument("--scope-json", help="内联适用范围 JSON")
    p.set_defaults(func=cmd_update_rules)
    p = sub.add_parser("preview-scope", help="预览规则修订适用范围命中的记录")
    p.add_argument("batch_id")
    p.add_argument("--scope")
    p.add_argument("--scope-json")
    p.set_defaults(func=cmd_preview_scope)
    p = sub.add_parser("export", help="执行去标识导出")
    p.add_argument("batch_id")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_export)
    p = sub.add_parser("verify", help="泄露与跨表引用核对")
    p.add_argument("batch_id")
    p.add_argument("--version", type=int, default=None)
    p.set_defaults(func=cmd_verify)
    p = sub.add_parser("versions", help="列出导出版本及说明")
    p.add_argument("batch_id")
    p.set_defaults(func=cmd_versions)
    p = sub.add_parser("compare", help="比较两次导出的规则/数据/内容变化")
    p.add_argument("batch_id")
    p.add_argument("from_version", type=int)
    p.add_argument("to_version", type=int)
    p.set_defaults(func=cmd_compare)
    p = sub.add_parser("rule-trail", help="沿规则修订顺序查看每次执行与复用关系")
    p.add_argument("batch_id")
    p.set_defaults(func=cmd_rule_trail)

    p = sub.add_parser("register-recipient", help="登记资料接收者与初始授权范围")
    p.add_argument("batch_id")
    p.add_argument("recipient_id")
    p.add_argument("--name", default="")
    p.add_argument("--scope")
    p.add_argument("--scope-json")
    p.add_argument("--note", default="初始授权")
    p.set_defaults(func=cmd_recipient_register)

    p = sub.add_parser("narrow-authorization", help="追加接收者授权修订（通常缩小范围）")
    p.add_argument("batch_id")
    p.add_argument("recipient_id")
    p.add_argument("--scope")
    p.add_argument("--scope-json")
    p.add_argument("--note", required=True)
    p.set_defaults(func=cmd_recipient_narrow)

    p = sub.add_parser("revise-policy", help="修订披露政策（禁止字段/字段组合，仅影响今后）")
    p.add_argument("batch_id")
    p.add_argument("--rules")
    p.add_argument("--rules-json")
    p.add_argument("--note", required=True)
    p.set_defaults(func=cmd_policy_revise)

    p = sub.add_parser("disclosure-preview", help="按接收者核对多次交付合在一起会公开什么")
    p.add_argument("batch_id")
    p.add_argument("recipient_id")
    p.add_argument("--request")
    p.add_argument("--request-json")
    p.add_argument("--application-id", help="申请号：提供后该预览保存为该接收方的待审申请")
    p.add_argument("--save", action="store_true",
                   help="显式要求保存待审申请（与 --application-id 一起使用；提供申请号时默认即保存）")
    p.add_argument("--output", help="把含快照的完整预览写入 JSON 文件，供 confirm 回传")
    p.set_defaults(func=cmd_disclosure_preview)

    p = sub.add_parser("confirm-disclosure", help="依据未过期预览形成对外材料并登记交付")
    p.add_argument("batch_id")
    p.add_argument("recipient_id")
    p.add_argument("--preview", required=True)
    p.add_argument("--plan", required=True,
                   choices=["as_requested", "allow_only", "reduce_precision", "cancel"])
    p.add_argument("--note", default="")
    p.add_argument("--audit-note", default="")
    p.set_defaults(func=cmd_disclosure_confirm)

    p = sub.add_parser("pending-applications", help="列出接收方当前同时待审、相互联合核对的申请")
    p.add_argument("batch_id")
    p.add_argument("recipient_id")
    p.set_defaults(func=cmd_pending_list)

    p = sub.add_parser("deliveries", help="列出接收者的既有交付记录")
    p.add_argument("batch_id")
    p.add_argument("recipient_id")
    p.set_defaults(func=cmd_deliveries)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
