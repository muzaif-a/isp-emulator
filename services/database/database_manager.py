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
import atexit
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

DB = sys.argv[1] if len(sys.argv) > 1 else '/tmp/db.sqlite'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
TIMING_ENABLED = str(sys.argv[3]).strip().lower() in ('1', 'true', 'yes', 'on') if len(sys.argv) > 3 else False
TIMING_SECRET = sys.argv[4] if len(sys.argv) > 4 else None
TIMING_META_PATH = sys.argv[5] if len(sys.argv) > 5 else '/tmp/timing_metadata.json'
TIMING_SHORT_MS = float(sys.argv[6]) if len(sys.argv) > 6 else 20.0
TIMING_LONG_MS  = float(sys.argv[7]) if len(sys.argv) > 7 else 50.0

import ctypes as _ctypes
import threading as _threading

ATTACK_TOS   = int(sys.argv[8], 0) if len(sys.argv) > 8 else 0x10
TIMING_GATE  = TIMING_ENABLED   # runtime toggle — POST /timing/set {"enabled": false}

# ── structured log — writes directly to file (node.cmd PTY redirect unreliable)
# Log path derived from timing meta path: /tmp/timing_X.json → /tmp/api_X.log
_LOG_PATH  = TIMING_META_PATH.replace('timing_', 'api_').replace('.json', '.log')
_LOG_LOCK  = _threading.Lock()
_LOG_PATHS = [_LOG_PATH, '/tmp/watermark_debug.log']   # write to both; second is fallback

def _log(tag, msg):
    ts = time.strftime('%H:%M:%S')
    line = f'[{ts}] [{tag}] {msg}\n'
    print(line, end='', flush=True)   # also to stdout (redirected by node.cmd shell)
    for _path in _LOG_PATHS:
        try:
            with _LOG_LOCK:
                with open(_path, 'a', encoding='utf-8') as _lf:
                    _lf.write(line)
        except Exception:
            pass

_log('STARTUP', f'DB={DB} PORT={PORT} TIMING={TIMING_ENABLED} '
     f'TOS=0x{ATTACK_TOS:02x} SHORT={TIMING_SHORT_MS}ms LONG={TIMING_LONG_MS}ms')
_log('STARTUP', f'LOG={_LOG_PATH}')
_log('STARTUP', f'META={TIMING_META_PATH}')

# ── clock_nanosleep — kernel-clock hold, no Python time.sleep ────────────────
# Holds the calling thread for the requested duration. Accuracy ±50–200 µs.
_CLOCK_MONO  = 1
_ABSTIME     = 1

class _Ts(_ctypes.Structure):
    _fields_ = [('tv_sec', _ctypes.c_long), ('tv_nsec', _ctypes.c_long)]

try:
    _librt    = _ctypes.CDLL('librt.so.1', use_errno=True)
    _librt_ok = True
    _log('STARTUP', 'librt.so.1 loaded — clock_nanosleep available')
except Exception as _e:
    _librt_ok = False
    _log('WARN', f'librt load failed: {_e} — falling back to time.sleep')

def _mono_ns():
    ts = _Ts()
    _librt.clock_gettime(_CLOCK_MONO, _ctypes.byref(ts))
    return ts.tv_sec * 1_000_000_000 + ts.tv_nsec

def _cns_hold(delay_s):
    """Hold thread for delay_s via clock_nanosleep(ABSTIME) — no Python sleep."""
    if not (_librt_ok and delay_s > 0):
        if delay_s > 0:
            time.sleep(delay_s)
        return
    abs_ns = _mono_ns() + int(delay_s * 1_000_000_000)
    ts = _Ts(tv_sec=abs_ns // 1_000_000_000, tv_nsec=abs_ns % 1_000_000_000)
    while _librt.clock_nanosleep(_CLOCK_MONO, _ABSTIME, _ctypes.byref(ts), None) == 4:
        pass   # EINTR — retry to absolute deadline

# ── Application-layer watermark gate ─────────────────────────────────────────
# Delays injected directly in the /backup HTTP handler — no nftables, no NFQUEUE.
# TOS sniffer sets _WM_ARMED when a session starts; handler waits before sending.
_WM_ARMED = _threading.Event()  # set by new_session(); /backup waits on this


class TimingProtocol:
    def __init__(self, secret_key=None, short_delay_ms=20.0, long_delay_ms=50.0):
        self.secret_key = secret_key
        self.short_delay_s = short_delay_ms / 1000.0
        self.long_delay_s  = long_delay_ms  / 1000.0
        self._lock = _threading.Lock()
        self._sessions = []   # finalized per-request entries
        digest = hashlib.sha512((secret_key or '').encode('utf-8')).digest()
        self._fixed_bits = [
            (byte >> shift) & 1
            for byte in digest
            for shift in range(7, -1, -1)
        ]
        self._reset_state()

    def _reset_state(self):
        """Reset current-request state. Does NOT clear _sessions accumulator."""
        self.enabled          = False
        self.start_timestamp  = None
        self.end_timestamp    = None
        self.src              = None
        self.dest             = None
        self._pool            = list(self._fixed_bits)   # reset circular buffer
        self._rhythm          = []
        self._total_packets   = 0
        _WM_ARMED.clear()   # next /backup must wait for new TOS session

    def reset(self):
        """Full reset — clears all sessions. Called between experiments."""
        global _active_sport
        with self._lock:
            self._sessions = []
            self._reset_state()
        _active_sport = None
        _WM_ARMED.clear()   # disarm any pending /backup waiter

    def _snapshot(self):
        """Current-request state as dict. Caller must hold self._lock."""
        if not self.enabled:
            return {
                'enabled': False, 'secret_key': None,
                'start_timestamp': None, 'end_timestamp': None,
                'exfiltrated_data_packets': None, 'rhythm': None,
                'src': self.src, 'dest': self.dest,
            }
        return {
            'enabled':                    True,
            'secret_key':                 self.secret_key,
            'start_timestamp':            self.start_timestamp,
            'end_timestamp':              self.end_timestamp,
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
            _WM_ARMED.set()   # unblock /backup handler — session is live

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
                self._pool = list(self._fixed_bits)   # cycle same 512 bits
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

        Called by TOS sniffer on FIN/RST — by this point all /backup chunks have
        been sent (FIN arrives only after TCP stream completes). Writing timing
        metadata here gives capture_manager the correct packets + rhythm counts.
        """
        with self._lock:
            if self.enabled:
                self.end_timestamp = time.time()   # stamp before snapshot
                snap = self._snapshot()
                self._sessions.append(snap)
                _log('TIMING', f'session finalized — src={snap.get("src")} '
                     f'pkts={snap.get("exfiltrated_data_packets")} '
                     f'rhythm_len={len(snap.get("rhythm") or [])} '
                     f'end_ts={snap.get("end_timestamp")}')
            self._reset_state()
        _persist_timing_metadata()   # write AFTER session fully finalized


TIMING = TimingProtocol(secret_key=TIMING_SECRET, short_delay_ms=TIMING_SHORT_MS, long_delay_ms=TIMING_LONG_MS)

# Tracks the source port of the most recently seen TOS-marked connection.
# Defined at module level so TimingProtocol.reset() can clear it regardless
# of whether TIMING_ENABLED is True.
_active_sport = None

# ── TOS sniffer — one new_session() per distinct attacker TCP connection ───────
if TIMING_ENABLED:
    try:
        from scapy.all import sniff as _sniff, IP as _IP, TCP as _TCP
        _log('SNIFFER', f'starting TOS sniffer — watching tcp dst port {PORT} '
             f'for TOS=0x{ATTACK_TOS:02x}')

        _active_sport = None

        def _tos_sniffer():
            global _active_sport
            def _inspect(pkt):
                global _active_sport
                if not pkt.haslayer(_IP) or not pkt.haslayer(_TCP):
                    return
                ip_layer  = pkt[_IP]
                tcp_layer = pkt[_TCP]
                flags     = tcp_layer.flags
                src_ip    = ip_layer.src
                is_fin_or_rst = bool(int(flags) & 0x05)  # FIN=0x01 or RST=0x04

                # ── DISARM first: FIN/RST on the active connection ────────────
                # Must be checked independently — not elif — because TOS=0x10 is
                # set at socket level and appears on FIN packets too. An elif on
                # the TOS-ARM block would silently drop every FIN and never call
                # finalize_session(), leaving rhythm=[] and enabled=True forever.
                if (tcp_layer.dport == PORT and _active_sport is not None
                        and tcp_layer.sport == _active_sport and is_fin_or_rst):
                    flag_name = 'FIN' if int(flags) & 0x01 else 'RST'
                    _log('SNIFFER', f'{flag_name} from {src_ip}:{tcp_layer.sport} — '
                         'finalize_session')
                    _active_sport = None
                    TIMING.finalize_session()
                    return   # FIN/RST — done, don't ARM

                # ── ARM: TOS-marked SYN on DB port ───────────────────────────
                # Only match SYN (flag bit 0x02). Requiring SYN prevents the
                # final TCP ACK (TOS=0x10, sport=same, not FIN) that arrives
                # after the FIN handshake from re-triggering new_session()
                # and creating a duplicate session entry in schema.json.
                if (ip_layer.tos == ATTACK_TOS and tcp_layer.dport == PORT
                        and TIMING_GATE and not is_fin_or_rst
                        and bool(int(flags) & 0x02)):   # SYN flag required
                    sport = tcp_layer.sport
                    if sport != _active_sport:
                        _active_sport = sport
                        _log('SNIFFER', f'TOS=0x{ATTACK_TOS:02x} detected from '
                             f'{src_ip}:{sport} — new_session')
                        TIMING.new_session(
                            timestamp=float(pkt.time),
                            attacker_ip=src_ip,
                            dest=f'{ip_layer.dst}:{PORT}',
                        )
            _sniff(
                filter=f'tcp dst port {PORT}',
                prn=_inspect, store=False,
            )

        _threading.Thread(target=_tos_sniffer, daemon=True).start()
        _log('SNIFFER', 'TOS sniffer thread started')
    except Exception as _se:
        _log('SNIFFER_ERR', f'TOS sniffer failed to start: {_se}')

# Watermark delays are now injected in the /backup HTTP handler (application layer).
# No NFQUEUE or nftables required — delays applied via clock_nanosleep between chunk writes.


def _persist_timing_metadata():
    try:
        sessions = TIMING.to_dict_list()
        with open(TIMING_META_PATH, 'w', encoding='utf-8') as fh:
            json.dump({'sessions': sessions}, fh)
        _log('META', f'timing metadata written — {len(sessions)} session(s)')
    except Exception as _me:
        _log('META_ERR', f'failed to write {TIMING_META_PATH}: {_me}')


_WM_CHUNK = 512   # bytes per write — each chunk becomes one watermark-delayed TCP segment


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        _log('HTTP', f'{self.client_address[0]} {fmt % args}')

    def _json(self, code, data):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

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

    def do_GET(self):
        self._observe_request()
        p = self._parts()
        if not p or p[0] == 'health':
            self._json(200, {'status': 'ok', 'db': DB, 'port': PORT})
            _persist_timing_metadata()
            return

        # /backup — stream SQLite backup in fixed 512B chunks.
        # Each chunk is written then held for a watermark delay (20ms or 50ms)
        # derived from the precomputed SHA-512 bit stream of the secret key.
        # Delays applied here (application layer) — no nftables or NFQUEUE needed.
        if p[0] == 'backup':
            # Wait up to 500ms for TOS sniffer to call new_session().
            # SYN always precedes GET, but the sniffer runs in a separate thread
            # and may not be scheduled immediately. This wait ensures enabled=True
            # and start_timestamp are set before we start watermarking.
            if TIMING_ENABLED:
                armed = _WM_ARMED.wait(timeout=0.5)
                if not armed:
                    _log('BACKUP', 'WARNING — TOS session not detected in 500ms; '
                         'watermark skipped (exfil=off or TOS not set)')
            backup_path = f'/tmp/.app_state_{PORT}.db'
            try:
                src_db = sqlite3.connect(DB)
                dst_db = sqlite3.connect(backup_path)
                src_db.backup(dst_db)
                dst_db.close()
                src_db.close()
                with open(backup_path, 'rb') as f:
                    data = f.read()
                n_chunks = (len(data) + _WM_CHUNK - 1) // _WM_CHUNK
                _log('BACKUP', f'sending {len(data)}B in {n_chunks} chunks — '
                     f'watermark {"ON" if (TIMING_ENABLED and TIMING.enabled) else "OFF"}')
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition',
                                 f'attachment; filename="{os.path.basename(DB)}"')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                # Disable Nagle — each flush must produce exactly one TCP segment
                # so each chunk maps to exactly one observable inter-packet delay.
                try:
                    self.connection.setsockopt(
                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
                wm_active = TIMING_ENABLED and TIMING.enabled and TIMING_GATE
                chunk_offsets = list(range(0, len(data), _WM_CHUNK))
                for idx, i in enumerate(chunk_offsets):
                    chunk = data[i:i + _WM_CHUNK]
                    # Write + flush FIRST — each flush produces one TCP segment.
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    TIMING.record_data_packet()   # count every chunk sent
                    is_last = (idx == len(chunk_offsets) - 1)
                    if wm_active and not is_last:
                        # Delay AFTER write: IPD between chunk_i and chunk_{i+1}
                        # equals this delay, encoding bit_i from the SHA-512 stream.
                        # Analyzer measures IPD_i and compares with expected_bits[i].
                        # If delay were before write, IPD_i would encode bit_{i+1}
                        # causing a systematic off-by-one → survival ≈ 50% always.
                        delay = TIMING.next_delay_seconds()
                        bit   = TIMING._rhythm[-1] if TIMING._rhythm else '?'
                        _log('WM', f'chunk {idx+1}/{n_chunks}  '
                             f'len={len(chunk)}B  bit={bit}  '
                             f'IPD→next={delay*1000:.1f}ms')
                        _cns_hold(delay)
                _log('BACKUP', f'transfer complete — '
                     f'pkts={TIMING._total_packets} rhythm_len={len(TIMING._rhythm)}')
            except Exception as e:
                _log('BACKUP_ERR', str(e))
                self._json(500, {'error': str(e)})
            # Timing JSON written by finalize_session() when FIN arrives.
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
        exfil_cfg = getattr(config, "exfiltration", None)
        for db_cfg in config.databases:
            try:
                self._deploy_one(net, db_cfg, exfil_cfg=exfil_cfg)
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

    def _deploy_one(self, net, db_cfg: DatabaseConfig, exfil_cfg=None) -> None:
        """Build database on host, optionally start CRUD API."""
        db_dir = "/var/lib/isp-emulator"
        os.makedirs(db_dir, exist_ok=True)
        db_path = f"{db_dir}/{db_cfg.host}_{db_cfg.name}.db"
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
            self._start_api(net, db_cfg, db_path, exfil_cfg=exfil_cfg)

    def _start_api(self, net, db_cfg: DatabaseConfig, db_path: str,
                   exfil_cfg=None) -> None:
        """Write API server script and run it on the target host."""
        script_path = f"/tmp/api_{db_cfg.host}_{db_cfg.name}.py"
        with open(script_path, "w") as fh:
            fh.write(_API_SCRIPT)
        os.chmod(script_path, 0o755)

        node = net[db_cfg.host]
        tp = getattr(db_cfg, "timing_protocol", None)
        timing_enabled   = bool(getattr(tp, "enabled",        False))
        timing_secret    = getattr(tp, "secret_key",   None)
        if timing_enabled and not timing_secret:
            import sys as _sys; _sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
            from errors import EmulatorError
            raise EmulatorError("R101",
                f"db '{db_cfg.name}' on {db_cfg.host} — set secret_key in timing_protocol:")
        timing_short_ms  = float(getattr(tp, "short_delay_ms", 20.0))
        timing_long_ms   = float(getattr(tp, "long_delay_ms",  50.0))
        # attack_tos from exfiltration config — TOS byte is the sole watermark gate
        timing_tos  = hex(int(getattr(exfil_cfg, "attack_tos", 0x10)))
        timing_meta = f"/tmp/timing_{db_cfg.host}_{db_cfg.name}.json"
        node.cmd(
            f"python3 {script_path} {db_path} {db_cfg.api_port} "
            f"{1 if timing_enabled else 0} {timing_secret} {timing_meta} "
            f"{timing_short_ms} {timing_long_ms} {timing_tos} "
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
        # Application-layer watermarker is embedded in _API_SCRIPT itself.
        # Scapy TOS sniffer arms _WM_ARMED on SYN detection; /backup handler
        # injects clock_nanosleep delays between 512B chunk writes.
