"""Synthetic row generator.

Given a TableConfig schema, generates `rows` realistic rows by calling
the per-field generators.  The `id` column is auto-handled as a
sequential integer regardless of how it's declared in the schema.
"""

import logging
from typing import Any, Dict, List

from config_loader import TableConfig
from .generators import generate

logger = logging.getLogger(__name__)


def generate_rows(table: TableConfig) -> List[Dict[str, Any]]:
    """Return a list of *table.rows* synthetic rows matching *table.schema*."""
    rows: List[Dict[str, Any]] = []

    for i in range(1, table.rows + 1):
        row: Dict[str, Any] = {}

        for col_name, field_type in table.schema.items():
            if col_name == "id":
                row["id"] = i          # always sequential
                continue
            val = generate(field_type, context=row)
            row[col_name] = val

        # Ensure id is present even if not declared
        if "id" not in row:
            row["id"] = i

        rows.append(row)

    logger.debug("Generated %d rows for table %s", len(rows), table.name)
    return rows
