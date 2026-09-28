"""命令行入口：python -m crp ..."""

from __future__ import annotations

import argparse
from pathlib import Path

from crp.audit import cross_table_consistency, scan_leaks
from crp.batch import BatchStore
from crp.exporter import Exporter
from crp.paths import Store
from crp.util import read_json


def _store(args: argparse.Namespace) -> Store:
    return Store.create(Path(args.data_root))


def cmd_init_batch(args: argparse.Namespace) -> None:
    config = read_json(Path(args.config))
    batch = BatchStore(_store(args)).create(config, note=args.note)
    print(f"已创建批次 {batch.batch_id}（字段规则 v{batch.rules_version}）")


def cmd_update_rules(args: argparse.Namespace) -> None:
    new_rules = read_json(Path(args.rules))
    batch = BatchStore(_store(args)).update_rules(args.batch_id, new_rules, note=args.note)
    print(f"批次 {batch.batch_id} 字段规则已更新至 v{batch.rules_version}（旧版本说明保留）")


def cmd_export(args: argparse.Namespace) -> None:
    result = Exporter(_store(args)).export_batch(args.batch_id, note=args.note)
    action = "复用既有" if result.reused else "生成新"
    print(f"{action}导出版本 v{result.version:03d}：{result.version_dir}")
    print(f"依据字段规则 v{result.rules_version}；版本说明：{result.note}")


def cmd_verify(args: argparse.Namespace) -> None:
    store = _store(args)
    index = read_json(store.export_index(args.batch_id))
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
    index_path = store.export_index(args.batch_id)
    if not index_path.exists():
        print("暂无导出版本")
        return
    index = read_json(index_path)
    for entry in index["versions"]:
        print(f"v{int(entry['version']):03d} 规则v{entry['rules_version']} {entry['created_at']} {entry['note']}")


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
    p.set_defaults(func=cmd_update_rules)
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
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
