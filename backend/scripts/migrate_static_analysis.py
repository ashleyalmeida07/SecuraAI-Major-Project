"""Add static-analysis provenance columns to the `findings` table.

`Base.metadata.create_all()` only creates missing *tables*, never missing
columns, so an existing NeonDB needs this one-off ALTER. Safe to re-run: every
statement is guarded with IF NOT EXISTS.

    uv run python scripts/migrate_static_analysis.py
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from app.db.session import engine

STATEMENTS = [
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS tool_source VARCHAR",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS rule_id VARCHAR",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS multi_tool_confirmed BOOLEAN DEFAULT FALSE",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS taint_path JSON",
    "CREATE INDEX IF NOT EXISTS ix_findings_tool_source ON findings (tool_source)",
]


def migrate() -> None:
    print("Applying static-analysis migration to findings table...")
    with engine.begin() as connection:
        for statement in STATEMENTS:
            print(f"  → {statement}")
            connection.execute(text(statement))
    print("Migration complete.")


if __name__ == "__main__":
    migrate()
