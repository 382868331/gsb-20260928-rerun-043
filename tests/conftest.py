import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from crp import exporter
from crp.storage import Project

EXAMPLES = ROOT / "examples"


@pytest.fixture()
def project(tmp_path):
    return Project.init(tmp_path)


def _setup_batch(project, batch_id: str = "demo", rules_file: Path | None = None, tables=None):
    exporter.create_batch(project, batch_id, "Demo study", "fictional data only")
    rules_path = rules_file or EXAMPLES / "rules-demo.json"
    import json

    exporter.put_rules(project, batch_id, json.loads(rules_path.read_text(encoding="utf-8")))
    tables = tables or ["demographics", "visits", "labs", "medications"]
    for table in tables:
        exporter.import_table(project, batch_id, table, EXAMPLES / "sample_data" / f"{table}.csv")
    return batch_id


@pytest.fixture()
def demo_batch(project):
    return _setup_batch(project)
