"""Build SQLite schema from TableConfig.

Maps YAML field generator types to SQLite column types.
"""

import logging
from typing import List

from config_loader import TableConfig

logger = logging.getLogger(__name__)

# generator_type -> SQLite column type
_TYPE_MAP = {
    "integer": "INTEGER",
    "int":     "INTEGER",
    "float":   "REAL",
    "salary":  "REAL",
    "price":   "REAL",
    "boolean": "INTEGER",  # SQLite has no BOOL
    "bool":    "INTEGER",
    "uuid":    "TEXT",
    "date":    "TEXT",
}


def column_sql_type(field_type: str) -> str:
    """Return the SQLite type for a generator field_type."""
    return _TYPE_MAP.get(field_type.lower(), "TEXT")


def build_create_table(table: TableConfig) -> str:
    """Return a CREATE TABLE SQL statement for *table*."""
    cols = []
    for col_name, field_type in table.schema.items():
        sql_type = column_sql_type(field_type)
        if col_name == "id":
            cols.append(f"  {col_name} {sql_type} PRIMARY KEY AUTOINCREMENT")
        else:
            cols.append(f"  {col_name} {sql_type}")

    # Ensure id column exists
    if "id" not in table.schema:
        cols.insert(0, "  id INTEGER PRIMARY KEY AUTOINCREMENT")

    col_block = ",\n".join(cols)
    ddl = f"CREATE TABLE IF NOT EXISTS {table.name} (\n{col_block}\n);"
    logger.debug("DDL for %s:\n%s", table.name, ddl)
    return ddl


def build_indexes(table: TableConfig) -> List[str]:
    """Return CREATE INDEX statements for declared indexes."""
    stmts = []
    for col in table.indexes:
        stmts.append(
            f"CREATE INDEX IF NOT EXISTS idx_{table.name}_{col} ON {table.name}({col});"
        )
    return stmts


def insert_sql(table_name: str, columns: List[str]) -> str:
    """Return a parameterised INSERT statement."""
    placeholders = ", ".join("?" * len(columns))
    col_list = ", ".join(columns)
    return f"INSERT INTO {table_name} ({col_list}) VALUES ({placeholders});"
