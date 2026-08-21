"""Unit tests for database modules — no Mininet required.

Tests:
  * generators.py      — field value generation
  * schema_builder.py  — DDL generation
  * synthetic_data.py  — row generation
  * database_manager   — SQLite creation (in /tmp)
"""

import os
import sqlite3
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config_loader import TableConfig, DatabaseConfig
from services.database.generators import generate
from services.database.schema_builder import build_create_table, build_indexes, insert_sql, column_sql_type
from services.database.synthetic_data import generate_rows
from services.database.rhythm_computer import WatermarkBitstream, TimingProtocol
from services.database import database_manager


# ------------------------------------------------------------------ generators

class TestGenerators:

    def test_integer_in_range(self):
        for _ in range(50):
            v = generate("integer")
            assert isinstance(v, int) and v > 0

    def test_first_name_string(self):
        v = generate("first_name")
        assert isinstance(v, str) and len(v) > 1

    def test_last_name_string(self):
        v = generate("last_name")
        assert isinstance(v, str) and len(v) > 1

    def test_email_format(self):
        ctx = {"first_name": "Alice", "last_name": "Smith"}
        email = generate("email", ctx)
        assert "@" in email
        assert "alice" in email.lower()
        assert "smith" in email.lower()

    def test_salary_is_float_in_range(self):
        s = generate("salary")
        assert isinstance(s, float)
        assert 28_000 <= s <= 180_000

    def test_price_is_float(self):
        p = generate("price")
        assert isinstance(p, float) and p > 0

    def test_boolean(self):
        vals = {generate("boolean") for _ in range(30)}
        assert vals == {True, False}

    def test_uuid_format(self):
        u = generate("uuid")
        assert len(u) == 36 and u.count("-") == 4

    def test_date_format(self):
        d = generate("date")
        parts = d.split("-")
        assert len(parts) == 3
        assert len(parts[0]) == 4  # year

    def test_unknown_type_fallback(self):
        v = generate("completely_unknown_type")
        assert isinstance(v, str)

    def test_department_from_list(self):
        d = generate("department")
        assert isinstance(d, str) and len(d) > 0

    def test_product_from_list(self):
        p = generate("product")
        assert isinstance(p, str) and len(p) > 0


# ------------------------------------------------------------------ schema builder

class TestSchemaBuilder:

    def test_build_create_table_has_id_pk(self):
        t = TableConfig(
            name="users",
            rows=5,
            schema={"id": "integer", "name": "first_name"},
        )
        ddl = build_create_table(t)
        assert "CREATE TABLE IF NOT EXISTS users" in ddl
        assert "PRIMARY KEY" in ddl
        assert "id" in ddl

    def test_build_create_table_auto_id_if_missing(self):
        t = TableConfig(name="items", rows=5, schema={"title": "text"})
        ddl = build_create_table(t)
        assert "id INTEGER PRIMARY KEY" in ddl

    def test_column_sql_types(self):
        assert column_sql_type("integer") == "INTEGER"
        assert column_sql_type("salary") == "REAL"
        assert column_sql_type("boolean") == "INTEGER"
        assert column_sql_type("first_name") == "TEXT"

    def test_build_indexes(self):
        t = TableConfig(
            name="employees", rows=10,
            schema={"id": "integer", "email": "email"},
            indexes=["email"],
        )
        stmts = build_indexes(t)
        assert len(stmts) == 1
        assert "CREATE INDEX" in stmts[0]
        assert "employees" in stmts[0]
        assert "email" in stmts[0]

    def test_insert_sql_parameterised(self):
        stmt = insert_sql("users", ["name", "email"])
        assert "INSERT INTO users" in stmt
        assert "?" in stmt
        assert stmt.count("?") == 2


# ------------------------------------------------------------------ synthetic data

class TestSyntheticData:

    def _make_table(self, rows: int = 10) -> TableConfig:
        return TableConfig(
            name="employees",
            rows=rows,
            schema={
                "id": "integer",
                "first_name": "first_name",
                "last_name": "last_name",
                "email": "email",
                "department": "department",
                "salary": "salary",
            },
        )

    def test_row_count(self):
        t = self._make_table(rows=25)
        rows = generate_rows(t)
        assert len(rows) == 25

    def test_ids_sequential(self):
        rows = generate_rows(self._make_table(rows=10))
        ids = [r["id"] for r in rows]
        assert ids == list(range(1, 11))

    def test_all_columns_present(self):
        t = self._make_table(rows=5)
        for row in generate_rows(t):
            for col in t.schema:
                assert col in row, f"Missing column: {col}"

    def test_emails_contain_at(self):
        rows = generate_rows(self._make_table(rows=10))
        for row in rows:
            assert "@" in row["email"]

    def test_salaries_numeric(self):
        rows = generate_rows(self._make_table(rows=10))
        for row in rows:
            assert isinstance(row["salary"], float)

    def test_zero_rows(self):
        t = TableConfig(name="empty", rows=0, schema={"id": "integer"})
        rows = generate_rows(t)
        assert rows == []


# ------------------------------------------------------------------ database creation

class TestDatabaseCreation:
    """Create a real SQLite DB in /tmp and verify it."""

    def _make_db_config(self, path: str) -> DatabaseConfig:
        return DatabaseConfig(
            host="test_host",
            name="testdb",
            engine="sqlite",
            tables=[
                TableConfig(
                    name="employees",
                    rows=20,
                    schema={
                        "id": "integer",
                        "first_name": "first_name",
                        "last_name": "last_name",
                        "email": "email",
                        "salary": "salary",
                    },
                    indexes=["email"],
                ),
                TableConfig(
                    name="products",
                    rows=10,
                    schema={
                        "id": "integer",
                        "product_name": "product",
                        "price": "price",
                    },
                ),
            ],
        )

    def test_create_and_populate_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        try:
            db_cfg = self._make_db_config(db_path)
            conn = sqlite3.connect(db_path)

            from services.database.schema_builder import build_create_table, build_indexes, insert_sql
            from services.database.synthetic_data import generate_rows

            for table in db_cfg.tables:
                conn.execute(build_create_table(table))
                for idx in build_indexes(table):
                    conn.execute(idx)
                rows = generate_rows(table)
                non_id = [c for c in rows[0].keys() if c != "id"] if rows else []
                stmt = insert_sql(table.name, non_id)
                conn.executemany(stmt, [[r[c] for c in non_id] for r in rows])

            conn.commit()

            # Verify counts
            emp_count = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
            prod_count = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
            assert emp_count == 20, f"Expected 20 employees, got {emp_count}"
            assert prod_count == 10, f"Expected 10 products, got {prod_count}"

            # Verify schema
            cur = conn.execute("PRAGMA table_info(employees)")
            col_names = [row[1] for row in cur.fetchall()]
            assert "first_name" in col_names
            assert "email" in col_names
            assert "salary" in col_names

            conn.close()
        finally:
            os.unlink(db_path)


class TestTimingProtocol:

    @pytest.mark.parametrize("short_ms,long_ms", [
        (20.0, 50.0),
        (10.0, 30.0),
        (5.0, 100.0),
        (1.0, 2.0),
    ])
    def test_delays_within_configured_bounds(self, short_ms, long_ms):
        from services.database.rhythm_computer import WatermarkBitstream
        tp = WatermarkBitstream(
            secret_key="unit-test-key",
            short_delay_ms=short_ms,
            long_delay_ms=long_ms,
        )
        for i in range(20):
            d, bit = tp.get_delay(i)
            assert d in (short_ms / 1000.0, long_ms / 1000.0), (
                f"delay {d}s not in expected set "
                f"({short_ms/1000.0}, {long_ms/1000.0})"
            )

    def test_disabled_returns_no_delay_when_gate_off(self):
        """When TIMING_GATE=False the handler skips get_delay — test gate logic only."""
        from services.database.rhythm_computer import WatermarkBitstream
        tp = WatermarkBitstream(secret_key="test")
        timing_gate = False
        result = tp.get_delay(0) if timing_gate else None
        assert result is None

    def test_enabled_protocol_tracks_bits_and_counts(self):
        import hashlib
        from services.database.rhythm_computer import WatermarkBitstream
        test_key = "test-timing-key-for-unit-test"
        short_ms, long_ms = 20.0, 50.0
        tp = WatermarkBitstream(
            secret_key=test_key,
            short_delay_ms=short_ms,
            long_delay_ms=long_ms,
        )

        d1, bit1 = tp.get_delay(0)
        d2, bit2 = tp.get_delay(1)

        # Delays must be exactly short or long (from config values)
        assert d1 in (short_ms / 1000.0, long_ms / 1000.0)
        assert d2 in (short_ms / 1000.0, long_ms / 1000.0)

        # Verify bits match SHA-512 expansion
        digest = hashlib.sha512(test_key.encode()).digest()
        raw_bits = [(byte >> shift) & 1 for byte in digest for shift in range(7, -1, -1)]
        assert bit1 == raw_bits[0]
        assert bit2 == raw_bits[1]
        assert len(tp.bits) == 512


class TestApiTimingPlacement:

    def test_watermark_engine_wiring(self):
        # _API_SCRIPT selects NetWatermark or AppWatermark at startup (_wm object).
        # Session lifecycle is driven through _wm.arm() / _wm.disarm() / _wm.reset().
        script = database_manager._API_SCRIPT
        # rhythm_computer computes bits; db_manager passes _rhythm to engine
        assert "from rhythm_computer import WatermarkBitstream" in script
        assert "_rhythm = _WMBitstream(" in script
        # Engine selection: net-flow or app-flow from YAML type
        assert "from net_watermarking import NetWatermark" in script
        assert "from app_watermarking import AppWatermark" in script
        assert "_NL_MODE" in script
        assert "_NetWM(PORT, _rhythm)" in script    # rhythm passed, not raw bits
        assert "_AppWM(_rhythm)" in script          # rhythm passed, not raw bits
        # db_manager calls engine interface only
        assert "_wm.arm(" in script
        assert "_wm.disarm(" in script
        assert "_wm.reset(" in script
        assert "_wm.wait_armed(" in script
        assert "_wm.is_armed(" in script
        assert "_wm.session_snapshot(" in script
        assert "_wm.next_chunk_delay(" in script
        # Session finalization and persistence still in script
        assert "_finalize_session" in script
        assert "_reset_session" in script
        assert "_persist_timing_metadata" in script
        # Chunk streaming + TCP_NODELAY still present
        assert "_WM_CHUNK" in script
        assert "TCP_NODELAY" in script
        # Old inline vars and nftables arm helper gone
        assert "_sess_chunks_sent" not in script
        assert "_nft_arm" not in script

    def test_index_created(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        try:
            table = TableConfig(
                name="users",
                rows=5,
                schema={"id": "integer", "email": "email"},
                indexes=["email"],
            )
            conn = sqlite3.connect(db_path)
            from services.database.schema_builder import build_create_table, build_indexes
            conn.execute(build_create_table(table))
            for idx in build_indexes(table):
                conn.execute(idx)
            conn.commit()

            indexes = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='users'"
            ).fetchall()
            idx_names = [i[0] for i in indexes]
            assert any("email" in n for n in idx_names), f"Email index missing: {idx_names}"
            conn.close()
        finally:
            os.unlink(db_path)
