"""Database lifecycle manager.

Orchestrates SQLite creation, schema building, synthetic data insertion,
and CRUD API server startup — all driven from DatabaseConfig.

In Mininet:  the SQLite file is written directly to /tmp/ on the shared
             filesystem; the API server script is also written to /tmp/
             and executed inside the Mininet host's network namespace.
"""

import json
import logging
import os
import sqlite3
import time
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from mininet.node import Node

from config_loader import DatabaseConfig, TopologyConfig
from .schema_builder import build_create_table, build_indexes, insert_sql
from .synthetic_data import generate_rows

logger = logging.getLogger(__name__)

# CRUD API server Python script (self-contained, no deps beyond stdlib)
_API_SCRIPT = r'''#!/usr/bin/env python3
"""Auto-generated CRUD REST API for SQLite — ISP emulator."""
import hashlib
import json
import os
import socket
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

DB = sys.argv[1] if len(sys.argv) > 1 else '/tmp/db.sqlite'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
TIMING_ENABLED = str(sys.argv[3]).strip().lower() in ('1', 'true', 'yes', 'on') if len(sys.argv) > 3 else False
TIMING_SECRET = sys.argv[4] if len(sys.argv) > 4 else 'example_key'
TIMING_META_PATH = sys.argv[5] if len(sys.argv) > 5 else '/tmp/timing_metadata.json'
TIMING_SHORT_MS = float(sys.argv[6]) if len(sys.argv) > 6 else 20.0
TIMING_LONG_MS  = float(sys.argv[7]) if len(sys.argv) > 7 else 50.0


import threading as _threading

ATTACK_TOS   = 0x10
TIMING_ARMED = TIMING_ENABLED
TIMING_GATE  = TIMING_ENABLED   # runtime toggle — POST /timing/set {"enabled": false}


class TimingProtocol:
    def __init__(self, secret_key='example_key', short_delay_ms=20.0, long_delay_ms=50.0):
        self.secret_key = secret_key
        self.short_delay_s = short_delay_ms / 1000.0
        self.long_delay_s  = long_delay_ms  / 1000.0
        self._lock = _threading.Lock()
        self._sessions = []   # finalized per-request entries
        self._reset_state()

    def _reset_state(self):
        """Reset current-request state. Does NOT clear _sessions accumulator."""
        self.enabled          = False
        self.start_timestamp  = None
        self.end_timestamp    = None
        self.src              = None
        self.dest             = None
        self._nonce           = 1
        self._pool            = []
        self._rhythm          = []
        self._nonces_used     = []
        self._total_packets   = 0

    def reset(self):
        """Full reset — clears all sessions. Called between experiments."""
        global _active_sport
        with self._lock:
            self._sessions = []
            self._reset_state()
        _active_sport = None

    def _snapshot(self):
        """Current-request state as dict. Caller must hold self._lock."""
        if not self.enabled:
            return {
                'enabled': False, 'secret_key': None,
                'start_timestamp': None, 'end_timestamp': None,
                'nonces_used': None,
                'exfiltrated_data_packets': None, 'rhythm': None,
                'src': self.src, 'dest': self.dest,
            }
        return {
            'enabled':                    True,
            'secret_key':                 self.secret_key,
            'start_timestamp':            self.start_timestamp,
            'end_timestamp':              self.end_timestamp,
            'nonces_used':                list(self._nonces_used),
            'exfiltrated_data_packets':   self._total_packets,
            'rhythm':                     list(self._rhythm),
            'src':                        self.src,
            'dest':                       self.dest,
            'short_delay_ms':             self.short_delay_s * 1000,
            'long_delay_ms':              self.long_delay_s  * 1000,
        }

    def new_session(self, timestamp, attacker_ip=None, dest=None):
        """Start timing for a new TOS-marked TCP connection.

        Finalizes any active session into _sessions, then resets and arms
        a fresh entry. One entry per distinct attacker TCP connection.
        """
        with self._lock:
            if self.enabled:
                if self._total_packets == 0 and not self._rhythm:
                    print(
                        f'[TIMING WARN] new_session() displaced a zero-packet '
                        f'session (src={self.src}). Two distinct TOS connections '
                        'arrived during one exfil — the attacker host is likely '
                        'also an NPC host. Upgrade to socket-level TOS marking.',
                        file=sys.stderr, flush=True,
                    )
                self._sessions.append(self._snapshot())
            self._reset_state()
            self.enabled          = True
            self.start_timestamp  = timestamp
            if attacker_ip:
                self.src = attacker_ip
            if dest:
                self.dest = dest

    def observe_first_request(self, now, src=None, dest=None):
        with self._lock:
            if self.start_timestamp is None:
                self.start_timestamp = now
            if src and not self.src:
                self.src = src
            if dest and not self.dest:
                self.dest = dest

    def record_end(self):
        """Record timestamp of last exfiltrated data packet dispatch."""
        if self.enabled:
            with self._lock:
                self.end_timestamp = time.time()

    def record_data_packet(self):
        if self.enabled:
            with self._lock:
                self._total_packets += 1

    def next_delay_seconds(self):
        if not self.enabled:
            return 0.0
        with self._lock:
            if not self._pool:
                digest = hashlib.sha512(
                    f'{self.secret_key}:{self._nonce}'.encode('utf-8')
                ).digest()
                bits = []
                for byte in digest:
                    for shift in range(7, -1, -1):
                        bits.append((byte >> shift) & 1)
                self._pool = bits
                self._nonces_used.append(self._nonce)
                self._nonce += 1
            bit = self._pool.pop(0)
            self._rhythm.append(bit)
        return self.short_delay_s if bit == 0 else self.long_delay_s

    def to_dict(self):
        with self._lock:
            return self._snapshot()

    def to_dict_list(self):
        """All sessions: finalized ones + current active (if any)."""
        with self._lock:
            result = list(self._sessions)
            if self.enabled:
                result.append(self._snapshot())
            return result

    def finalize_session(self):
        """Finalize active request: archive snapshot, reset enabled=False.

        Called after each response is fully sent so the next non-TOS request
        starts with enabled=False instead of inheriting the previous state.
        """
        with self._lock:
            if self.enabled:
                self._sessions.append(self._snapshot())
            self._reset_state()


TIMING = TimingProtocol(secret_key=TIMING_SECRET, short_delay_ms=TIMING_SHORT_MS, long_delay_ms=TIMING_LONG_MS)

# Tracks the source port of the most recently seen TOS-marked connection.
# Defined at module level so TimingProtocol.reset() can clear it regardless
# of whether TIMING_ARMED is True.
_active_sport = None

# ── TOS sniffer — one new_session() per distinct attacker TCP connection ───────
if TIMING_ARMED:
    import threading as _threading
    try:
        from scapy.all import sniff as _sniff, IP as _IP, TCP as _TCP

        _active_sport = None

        def _tos_sniffer():
            global _active_sport
            def _inspect(pkt):
                global _active_sport
                if not TIMING_GATE:
                    return
                if pkt.haslayer(_IP) and pkt.haslayer(_TCP):
                    if pkt[_IP].tos == ATTACK_TOS and pkt[_TCP].dport == PORT:
                        sport = pkt[_TCP].sport
                        if sport != _active_sport:
                            _active_sport = sport
                            TIMING.new_session(
                                timestamp=float(pkt.time),
                                attacker_ip=pkt[_IP].src,
                                dest=f'{pkt[_IP].dst}:{PORT}',
                            )
            _sniff(
                filter=f'tcp dst port {PORT} and ip[1] = {ATTACK_TOS}',
                prn=_inspect, store=False,
            )

        _threading.Thread(target=_tos_sniffer, daemon=True).start()
    except Exception:
        pass   # scapy unavailable — fall back to YAML-only enable


def _persist_timing_metadata():
    try:
        with open(TIMING_META_PATH, 'w', encoding='utf-8') as fh:
            json.dump({'sessions': TIMING.to_dict_list()}, fh)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, data):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self._write_body_with_ipd(body)

    def _parts(self):
        return [p for p in self.path.split('?')[0].split('/') if p]

    def _conn(self):
        c = sqlite3.connect(DB)
        c.row_factory = sqlite3.Row
        return c

    def _body(self):
        n = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def _observe_request(self):
        src_ip = self.client_address[0] if self.client_address else None
        try:
            local_ip = self.connection.getsockname()[0]
        except Exception:
            local_ip = None
        dest = f'{local_ip}:{PORT}' if local_ip else f'0.0.0.0:{PORT}'
        TIMING.observe_first_request(time.time(), src=src_ip, dest=dest)

    def _write_body_with_ipd(self, body: bytes, chunk_size: int = 1200):
        if not body:
            return

        # Reduce Nagle coalescing so flushes map more closely to packet emission.
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        chunks = [body[i:i + chunk_size] for i in range(0, len(body), chunk_size)]

        # First payload chunk must be immediate (no timing delay).
        self.wfile.write(chunks[0])
        self.wfile.flush()
        TIMING.record_data_packet()

        # Subsequent payload chunks carry the timing protocol inter-packet delay.
        for chunk in chunks[1:]:
            TIMING.record_data_packet()
            delay = TIMING.next_delay_seconds()
            if delay > 0:
                time.sleep(delay)
            self.wfile.write(chunk)
            self.wfile.flush()

        # Stamp end of last exfiltrated packet for timing window calculation.
        TIMING.record_end()

    def do_GET(self):
        self._observe_request()
        p = self._parts()
        if not p or p[0] == 'health':
            self._json(200, {'status': 'ok', 'db': DB, 'port': PORT})
            _persist_timing_metadata()
            return
        if p[0] != 'api' or len(p) < 2:
            self._json(404, {'error': 'not found'})
            _persist_timing_metadata()
            return
        table = p[1]
        try:
            c = self._conn()
            if len(p) >= 3:
                row = c.execute(f'SELECT * FROM {table} WHERE id=?', (p[2],)).fetchone()
                self._json(200 if row else 404, dict(row) if row else {'error': 'not found'})
            else:
                rows = [dict(r) for r in c.execute(f'SELECT * FROM {table}').fetchall()]
                self._json(200, rows)
            c.close()
        except Exception as e:
            self._json(500, {'error': str(e)})
        TIMING.finalize_session()
        _persist_timing_metadata()

    def do_POST(self):
        self._observe_request()
        p = self._parts()
        # Timing set endpoint — update short/long delay and enabled flag at runtime
        if p and p[0] == 'timing' and len(p) > 1 and p[1] == 'set':
            global TIMING_GATE
            body = self._body()
            if 'short_delay_ms' in body:
                TIMING.short_delay_s = float(body['short_delay_ms']) / 1000.0
            if 'long_delay_ms' in body:
                TIMING.long_delay_s = float(body['long_delay_ms']) / 1000.0
            if 'enabled' in body:
                TIMING_GATE = bool(body['enabled'])
                if not TIMING_GATE:
                    TIMING.reset()
                    TIMING.enabled = False
            self._json(200, {
                'status': 'ok',
                'enabled':        TIMING_GATE,
                'short_delay_ms': TIMING.short_delay_s * 1000,
                'long_delay_ms':  TIMING.long_delay_s  * 1000,
            })
            return

        # Timing reset endpoint — called between experiment sessions
        if p and p[0] == 'timing' and len(p) > 1 and p[1] == 'reset':
            TIMING.reset()
            try:
                os.remove(TIMING_META_PATH)
            except FileNotFoundError:
                pass
            _persist_timing_metadata()
            self._json(200, {'status': 'reset'})
            return
        p = self._parts()
        if p[0] != 'api' or len(p) < 2:
            self._json(404, {'error': 'not found'})
            _persist_timing_metadata()
            return
        table, body = p[1], self._body()
        body.pop('id', None)
        try:
            c = self._conn()
            cols = ', '.join(body.keys())
            phs = ', '.join('?' * len(body))
            cur = c.execute(f'INSERT INTO {table}({cols}) VALUES({phs})', list(body.values()))
            c.commit()
            self._json(201, {'id': cur.lastrowid})
            c.close()
        except Exception as e:
            self._json(500, {'error': str(e)})
        _persist_timing_metadata()

    def do_PUT(self):
        self._observe_request()
        p = self._parts()
        if p[0] != 'api' or len(p) < 3:
            self._json(400, {'error': 'need /api/table/id'})
            _persist_timing_metadata()
            return
        table, rid, body = p[1], p[2], self._body()
        body.pop('id', None)
        try:
            c = self._conn()
            sets = ', '.join(f'{k}=?' for k in body)
            c.execute(f'UPDATE {table} SET {sets} WHERE id=?', list(body.values()) + [rid])
            c.commit()
            self._json(200, {'updated': rid})
            c.close()
        except Exception as e:
            self._json(500, {'error': str(e)})
        _persist_timing_metadata()

    def do_DELETE(self):
        self._observe_request()
        p = self._parts()
        if p[0] != 'api' or len(p) < 3:
            self._json(400, {'error': 'need /api/table/id'})
            _persist_timing_metadata()
            return
        table, rid = p[1], p[2]
        try:
            c = self._conn()
            c.execute(f'DELETE FROM {table} WHERE id=?', (rid,))
            c.commit()
            self._json(200, {'deleted': rid})
            c.close()
        except Exception as e:
            self._json(500, {'error': str(e)})
        _persist_timing_metadata()


if not os.path.exists(TIMING_META_PATH):
    _persist_timing_metadata()

HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
'''


class DatabaseManager:
    """Create, populate, and expose SQLite databases in a Mininet topology."""

    def __init__(self) -> None:
        # host_name -> {db_name -> db_path}
        self._dbs: Dict[str, Dict[str, str]] = {}
        # host_name -> {db_name -> port} — for databases with API
        self._api_ports: Dict[str, Dict[str, int]] = {}

    # ----------------------------------------------------------------- public

    def deploy_all(
        self,
        net,  # Mininet
        config: TopologyConfig,
    ) -> None:
        """Create and populate all databases declared in the config."""
        for db_cfg in config.databases:
            try:
                self._deploy_one(net, db_cfg)
            except Exception as exc:
                logger.error("DB deploy failed for %s@%s: %s", db_cfg.name, db_cfg.host, exc)

    def verify_all(self, config: TopologyConfig) -> bool:
        """Return True if every declared database file exists and is valid."""
        ok = True
        for db_cfg in config.databases:
            path = self._dbs.get(db_cfg.host, {}).get(db_cfg.name)
            if not path or not os.path.exists(path):
                logger.warning("DB missing: %s@%s", db_cfg.name, db_cfg.host)
                ok = False
                continue
            try:
                conn = sqlite3.connect(path)
                for t in db_cfg.tables:
                    count = conn.execute(f"SELECT COUNT(*) FROM {t.name}").fetchone()[0]
                    logger.info("DB verify: %s.%s has %d rows", db_cfg.name, t.name, count)
                conn.close()
            except Exception as exc:
                logger.error("DB verify error %s: %s", db_cfg.name, exc)
                ok = False
        return ok

    def get_db_path(self, host: str, db_name: str) -> Optional[str]:
        return self._dbs.get(host, {}).get(db_name)

    def get_api_port(self, host: str, db_name: str) -> Optional[int]:
        return self._api_ports.get(host, {}).get(db_name)

    # --------------------------------------------------------------- internals

    def _deploy_one(self, net, db_cfg: DatabaseConfig) -> None:
        """Build database on host, optionally start CRUD API."""
        db_path = f"/tmp/{db_cfg.host}_{db_cfg.name}.db"
        logger.info("Creating DB %s on %s → %s", db_cfg.name, db_cfg.host, db_path)

        # Build locally (shared filesystem with Mininet hosts)
        conn = sqlite3.connect(db_path)
        for table in db_cfg.tables:
            ddl = build_create_table(table)
            conn.execute(ddl)
            for idx_sql in build_indexes(table):
                conn.execute(idx_sql)

            rows = generate_rows(table)
            if rows:
                # Build insert excluding 'id' (autoincrement)
                non_id = [c for c in rows[0].keys() if c != "id"]
                stmt = insert_sql(table.name, non_id)
                conn.executemany(stmt, [[r[c] for c in non_id] for r in rows])
            logger.info(
                "  Table %s.%s: %d rows created", db_cfg.name, table.name, len(rows)
            )
        conn.commit()
        conn.close()

        self._dbs.setdefault(db_cfg.host, {})[db_cfg.name] = db_path

        # Start CRUD API if port configured
        if db_cfg.api_port:
            self._start_api(net, db_cfg, db_path)

    def _start_api(self, net, db_cfg: DatabaseConfig, db_path: str) -> None:
        """Write API server script and run it on the target host."""
        script_path = f"/tmp/api_{db_cfg.host}_{db_cfg.name}.py"
        with open(script_path, "w") as fh:
            fh.write(_API_SCRIPT)
        os.chmod(script_path, 0o755)

        node = net[db_cfg.host]
        tp = getattr(db_cfg, "timing_protocol", None)
        timing_enabled   = bool(getattr(tp, "enabled",        False))
        timing_secret    = getattr(tp, "secret_key",   "example_key")
        timing_short_ms  = float(getattr(tp, "short_delay_ms", 20.0))
        timing_long_ms   = float(getattr(tp, "long_delay_ms",  50.0))
        timing_meta = f"/tmp/timing_{db_cfg.host}_{db_cfg.name}.json"
        node.cmd(
            f"python3 {script_path} {db_path} {db_cfg.api_port} "
            f"{1 if timing_enabled else 0} {timing_secret} {timing_meta} "
            f"{timing_short_ms} {timing_long_ms} "
            f"> /tmp/api_{db_cfg.host}_{db_cfg.name}.log 2>&1 &"
        )
        time.sleep(0.5)

        # Quick health check
        check = node.cmd(
            f"curl -sf http://127.0.0.1:{db_cfg.api_port}/health 2>/dev/null"
        ).strip()
        if '"ok"' in check or "ok" in check:
            logger.info("CRUD API up: %s:%d (%s)", db_cfg.host, db_cfg.api_port, db_cfg.name)
        else:
            logger.warning(
                "CRUD API may not be ready yet: %s:%d (check /tmp/api_*.log)",
                db_cfg.host, db_cfg.api_port,
            )

        self._api_ports.setdefault(db_cfg.host, {})[db_cfg.name] = db_cfg.api_port
