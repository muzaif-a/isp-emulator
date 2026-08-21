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
# watermark type from YAML timing_protocol.type: "net-flow" | "app-flow" | "auto"
TIMING_WM_TYPE = sys.argv[9].strip().lower() if len(sys.argv) > 9 else 'auto'
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

# ── Precomputed rhythm via rhythm_computer.WatermarkBitstream ────────────────
# rhythm_computer.py owns the SHA-512 → 512-bit expansion and delay lookup.
# db_manager gets _rhythm and passes it to the chosen engine.
# Engines call _rhythm.get_delay(idx) — mod-512 rotation is inside WatermarkBitstream.
sys.path.insert(0, '/tmp')
from rhythm_computer import WatermarkBitstream as _WMBitstream
_rhythm = _WMBitstream(TIMING_SECRET or '', TIMING_SHORT_MS, TIMING_LONG_MS)
_log('STARTUP', f'rhythm precomputed — {len(_rhythm.bits)} bits from SHA-512(secret)')

# ── Watermark engine — selected by TIMING_WM_TYPE from YAML timing_protocol.type ─
# Both NetWatermark and AppWatermark expose the same interface:
#   arm(), disarm(), reset(), is_armed(), wait_armed(), session_snapshot()
# Drop-in replaceable: swap _wm to change mode without touching the rest of the script.
#
# TIMING_WM_TYPE:
#   "net-flow"  → force NetWatermark (NFQUEUE); hard-fail if unavailable
#   "app-flow"  → force AppWatermark (delays in /backup handler)
#   "auto"      → try NetWatermark first, fall back to AppWatermark silently
_wm      = None
_NL_MODE = False

if TIMING_ENABLED:
    if TIMING_WM_TYPE in ('net-flow', 'auto'):
        try:
            from net_watermarking import NetWatermark as _NetWM
            _wm = _NetWM(PORT, _rhythm)   # rhythm owns bits + delay lookup
            if _wm.setup():
                _NL_MODE = True
                atexit.register(_wm.teardown)
                _log('WM', f'network-layer (net-flow) ON — nft table wm_{PORT} queue {PORT % 100}')
            else:
                _wm = None
                raise RuntimeError('NetWatermark.setup() returned False')
        except Exception as _nw_e:
            if TIMING_WM_TYPE == 'net-flow':
                raise RuntimeError(f'net-flow requested but failed: {_nw_e}')
            _wm = None
            _log('WM', f'net-flow unavailable ({_nw_e}) — falling back to app-flow')

    if _wm is None:   # app-flow forced, or net-flow fell back
        from app_watermarking import AppWatermark as _AppWM
        _wm = _AppWM(_rhythm)   # rhythm owns bits + delay lookup
        _log('WM', f'app-layer (app-flow) ON — delays injected in /backup handler')

_log('WM', f'engine={_wm.MODE if _wm else "none"} type={TIMING_WM_TYPE} NL_MODE={_NL_MODE}')

# ── Session finalization ──────────────────────────────────────────────────────
_all_sessions = []          # finalized session dicts
_sess_lock    = _threading.Lock()
_active_sport = None        # sport of current TOS connection; None when idle


def _finalize_session():
    """Snapshot _wm session into _all_sessions and persist. Called on FIN/RST."""
    if not _wm.is_armed():
        return
    snap = _wm.session_snapshot()
    snap['end_timestamp'] = time.time()
    with _sess_lock:
        _all_sessions.append(snap)
    _log('SNIFFER', f'session finalized — attacker={snap["attacker_ip"]} '
         f'pkts={snap["exfiltrated_data_packets"]} '
         f'rhythm_len={len(snap["rhythm"])} '
         f'end_ts={snap["end_timestamp"]:.3f}')
    _wm.disarm()
    _persist_timing_metadata()


def _reset_session():
    """Clear all per-session state. Called between experiments via /timing/reset."""
    global _active_sport, _all_sessions
    if _wm:
        _wm.reset()
    with _sess_lock:
        _all_sessions  = []
        _active_sport  = None


# ── TOS sniffer — calls _wm.arm() on SYN, _finalize_session() on FIN/RST ─────
if TIMING_ENABLED:
    try:
        from scapy.all import sniff as _sniff, IP as _IP, TCP as _TCP
        _log('SNIFFER', f'starting TOS sniffer — watching tcp dst port {PORT} '
             f'for TOS=0x{ATTACK_TOS:02x}')

        def _tos_sniffer():
            global _active_sport

            def _inspect(pkt):
                global _active_sport
                if not pkt.haslayer(_IP) or not pkt.haslayer(_TCP):
                    return
                ip_layer      = pkt[_IP]
                tcp_layer     = pkt[_TCP]
                flags         = tcp_layer.flags
                src_ip        = ip_layer.src
                is_fin_or_rst = bool(int(flags) & 0x05)   # FIN=0x01, RST=0x04

                # ── DISARM: FIN/RST on active connection ──────────────────────
                # Checked independently — TOS=0x10 is set at socket level so
                # FIN packets also carry it; without this check every FIN silently
                # falls through to ARM and creates a duplicate session entry.
                if (tcp_layer.dport == PORT
                        and _active_sport is not None
                        and tcp_layer.sport == _active_sport
                        and is_fin_or_rst):
                    flag_name = 'FIN' if int(flags) & 0x01 else 'RST'
                    _log('SNIFFER', f'{flag_name} from {src_ip}:{tcp_layer.sport} '
                         '— finalizing session')
                    _active_sport = None
                    _finalize_session()
                    return

                # ── ARM: TOS-marked SYN on DB port ───────────────────────────
                # SYN flag (0x02) required — prevents the post-FIN ACK from
                # re-arming a new session and creating a duplicate schema entry.
                if (ip_layer.tos == ATTACK_TOS
                        and tcp_layer.dport == PORT
                        and TIMING_GATE
                        and not is_fin_or_rst
                        and bool(int(flags) & 0x02)):
                    sport = tcp_layer.sport
                    if sport != _active_sport:
                        _active_sport = sport
                        _log('SNIFFER', f'TOS=0x{ATTACK_TOS:02x} SYN from '
                             f'{src_ip}:{sport} — arming session')
                        _wm.arm(attacker_ip=src_ip, start_ts=float(pkt.time))

            _sniff(filter=f'tcp dst port {PORT}', prn=_inspect, store=False)

        _threading.Thread(target=_tos_sniffer, daemon=True).start()
        _log('SNIFFER', 'TOS sniffer thread started')
    except Exception as _se:
        _log('SNIFFER_ERR', f'TOS sniffer failed to start: {_se}')


def _persist_timing_metadata():
    """Write all finalized sessions (+ active if in-progress) to disk."""
    try:
        with _sess_lock:
            sessions = list(_all_sessions)
        # Include active session if data has been sent but FIN not yet seen
        if _wm and _wm.is_armed():
            snap = _wm.session_snapshot()
            if snap.get('exfiltrated_data_packets', 0) > 0:
                sessions.append(snap)
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

    def do_GET(self):
        p = self._parts()
        if not p or p[0] == 'health':
            self._json(200, {'status': 'ok', 'db': DB, 'port': PORT})
            _persist_timing_metadata()
            return

        # /backup — stream SQLite backup in 512B chunks with watermark delays.
        # Delays are applied AFTER each chunk write so IPD_i = delay_i = f(bit_i).
        # Rhythm precomputed at startup; sniffer arms _WM_ARMED on TOS SYN.
        if p[0] == 'backup':
            # SYN always precedes GET, but the sniffer runs in a separate thread.
            # Wait up to 500ms to guarantee arm() has been called and attacker_ip set.
            # If exfil=off (no TOS SYN ever arrives), proceed without watermark.
            if TIMING_ENABLED:
                armed = _wm.wait_armed(timeout=0.5)
                if not armed:
                    _log('BACKUP', 'WARNING — TOS SYN not detected in 500ms; '
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
                wm_active = TIMING_ENABLED and _wm.is_armed() and TIMING_GATE
                _log('BACKUP', f'sending {len(data)}B in {n_chunks} chunks — '
                     f'watermark {"ON" if wm_active else "OFF"}')
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition',
                                 f'attachment; filename="{os.path.basename(DB)}"')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                # Disable Nagle — each flush produces exactly one TCP segment so
                # each chunk maps to exactly one observable inter-packet delay.
                try:
                    self.connection.setsockopt(
                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
                chunk_offsets = list(range(0, len(data), _WM_CHUNK))
                if _NL_MODE:
                    # Network-layer: NetWatermark._callback() intercepts each outgoing
                    # TCP segment and applies the rhythm delay before the kernel sends it.
                    # This handler just streams — delays and counts are in net_watermarking.py.
                    for i in chunk_offsets:
                        self.wfile.write(data[i:i + _WM_CHUNK])
                        self.wfile.flush()
                    _log('BACKUP', f'NL stream done — {n_chunks} chunks sent to NFQUEUE')
                else:
                    # App-layer: AppWatermark.next_chunk_delay() writes delay AFTER each
                    # chunk (IPD_i = delay_i = f(bit_i)). Last chunk gets no delay.
                    # Delay-before-write causes off-by-one → survival ≈ 50% → NOT_DETECTED.
                    for idx, i in enumerate(chunk_offsets):
                        chunk   = data[i:i + _WM_CHUNK]
                        is_last = (idx == len(chunk_offsets) - 1)
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        if wm_active and not is_last:
                            delay, bit = _wm.next_chunk_delay()   # sleeps internally
                            _log('WM', f'chunk {idx+1}/{n_chunks} '
                                 f'len={len(chunk)}B bit={bit} '
                                 f'IPD→next={delay*1000:.1f}ms')
                snap = _wm.session_snapshot()
                _log('BACKUP', f'transfer complete — '
                     f'pkts={snap["exfiltrated_data_packets"]} '
                     f'bits_used={len(snap["rhythm"])}')
            except Exception as e:
                _log('BACKUP_ERR', str(e))
                self._json(500, {'error': str(e)})
            # Timing JSON is written by _finalize_session() when FIN arrives.
            return

        if p[0] != 'api' or len(p) < 2:
            self._json(404, {'error': 'not found'})
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

    def do_POST(self):
        p = self._parts()
        # /timing/set — update delay values and gate at runtime
        if p and p[0] == 'timing' and len(p) > 1 and p[1] == 'set':
            global TIMING_GATE
            body = self._body()
            # Update delays directly on _rhythm — both engines read from it.
            if 'short_delay_ms' in body:
                _rhythm.short_delay_s = float(body['short_delay_ms']) / 1000.0
            if 'long_delay_ms' in body:
                _rhythm.long_delay_s  = float(body['long_delay_ms']) / 1000.0
            if 'enabled' in body:
                TIMING_GATE = bool(body['enabled'])
                if not TIMING_GATE:
                    _reset_session()
            self._json(200, {
                'status': 'ok',
                'enabled':        TIMING_GATE,
                'short_delay_ms': _rhythm.short_delay_s * 1000,
                'long_delay_ms':  _rhythm.long_delay_s  * 1000,
            })
            return

        # /timing/reset — clear all session state between experiments
        if p and p[0] == 'timing' and len(p) > 1 and p[1] == 'reset':
            _reset_session()
            try:
                os.remove(TIMING_META_PATH)
            except FileNotFoundError:
                pass
            _persist_timing_metadata()
            self._json(200, {'status': 'reset'})
            return

        if p[0] != 'api' or len(p) < 2:
            self._json(404, {'error': 'not found'})
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

    def do_PUT(self):
        p = self._parts()
        if p[0] != 'api' or len(p) < 3:
            self._json(400, {'error': 'need /api/table/id'})
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

    def do_DELETE(self):
        p = self._parts()
        if p[0] != 'api' or len(p) < 3:
            self._json(400, {'error': 'need /api/table/id'})
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
        """Write API server script and watermark modules, then run on target host."""
        import shutil
        script_path = f"/tmp/api_{db_cfg.host}_{db_cfg.name}.py"
        with open(script_path, "w") as fh:
            fh.write(_API_SCRIPT)
        os.chmod(script_path, 0o755)
        # Copy watermark modules to /tmp so _API_SCRIPT subprocess can import them.
        # rhythm_computer  → computes 512 bits from secret_key
        # app_watermarking → AppWatermark: delays in /backup HTTP handler
        # net_watermarking → NetWatermark: delays via NFQUEUE before kernel sends
        _here = os.path.dirname(os.path.abspath(__file__))
        for _mod in ("rhythm_computer.py", "app_watermarking.py", "net_watermarking.py"):
            shutil.copy(os.path.join(_here, _mod), f"/tmp/{_mod}")

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
        timing_wm_type = getattr(tp, "watermark_type", "auto")  # net-flow | app-flow | auto
        node.cmd(
            f"python3 {script_path} {db_path} {db_cfg.api_port} "
            f"{1 if timing_enabled else 0} {timing_secret} {timing_meta} "
            f"{timing_short_ms} {timing_long_ms} {timing_tos} {timing_wm_type} "
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
        # Watermark engine selected at DB startup: NetWatermark (network-layer via NFQUEUE)
        # if available, else AppWatermark (app-layer delays in /backup handler).
        # Both modules are copied to /tmp/ above so the subprocess can import them.
