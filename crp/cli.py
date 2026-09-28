"""Command-line interface (offline files only, no hospital-system access)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import exporter
from .storage import Project, ProjectError, read_json
from .verify import check_cross_table_references, reconcile_exports


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="crp", description="Clinical research de-identified export platform")
    parser.add_argument("--root", default=".", help="project root directory")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize a project (private + export areas)")

    p = sub.add_parser("batch", help="create a study batch")
    p.add_argument("batch_id")
    p.add_argument("--title", required=True)
    p.add_argument("--description", default="")

    p = sub.add_parser("rules", help="store a new version of field rules (JSON file)")
    p.add_argument("batch_id")
    p.add_argument("rules_file")

    p = sub.add_parser("import", help="import an offline CSV table into a batch")
    p.add_argument("batch_id")
    p.add_argument("table")
    p.add_argument("csv_file")

    p = sub.add_parser("export", help="produce a new immutable de-identified export")
    p.add_argument("batch_id")
    p.add_argument("--note", required=True)

    p = sub.add_parser("versions", help="list export versions of a batch")
    p.add_argument("batch_id")

    p = sub.add_parser("verify-refs", help="check subject links across exported tables")
    p.add_argument("batch_id")
    p.add_argument("--version", type=int, required=True)

    p = sub.add_parser("reconcile", help="reconcile two repeated exports")
    p.add_argument("batch_id")
    p.add_argument("--old", dest="old", type=int, required=True)
    p.add_argument("--new", dest="new", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            project = Project.init(args.root)
            _print({"initialized": str(project.root)})
            return 0

        project = Project.open(args.root)
        if args.command == "batch":
            batch = exporter.create_batch(project, args.batch_id, args.title, args.description)
            _print({"batch_id": batch["id"], "created_at": batch["created_at"]})
        elif args.command == "rules":
            payload = read_json(Path(args.rules_file))
            version = exporter.put_rules(project, args.batch_id, payload)
            _print({"batch_id": args.batch_id, "rule_version": version})
        elif args.command == "import":
            _print(exporter.import_table(project, args.batch_id, args.table, args.csv_file))
        elif args.command == "export":
            _print(exporter.run_export(project, args.batch_id, args.note))
        elif args.command == "versions":
            batch = project.load_batch(args.batch_id)
            _print(batch["version_notes"])
        elif args.command == "verify-refs":
            export_dir = project.export_version_dir(args.batch_id, args.version)
            report = check_cross_table_references(export_dir).to_dict()
            _print(report)
            return 0 if report["consistent"] else 2
        elif args.command == "reconcile":
            _print(reconcile_exports(project, args.batch_id, args.old, args.new).to_dict())
        return 0
    except ProjectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
