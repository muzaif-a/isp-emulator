"""Service Manager — orchestrates deployment of all declared services.

Three deployment modes (from topology YAML):
  auto   : deploy + verify everything automatically.
  manual : configure network only; user starts services in CLI.
  hybrid : configure network; user starts services; manager discovers them.
"""

import logging
import os
import time
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from mininet.net import Mininet

from config_loader import ServiceConfig, TopologyConfig
from services.service_registry import ServiceRegistry, effective_port

logger = logging.getLogger(__name__)

# -------------------------------------------------- per-service Python scripts

_HTTP_SCRIPT = """\
#!/usr/bin/env python3
import sys, os
from http.server import HTTPServer, SimpleHTTPRequestHandler
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
os.makedirs('/tmp/www', exist_ok=True)
with open('/tmp/www/index.html', 'w') as f:
    f.write('<html><body><h1>ISP emulator HTTP Server</h1>'
            '<p>Host: {HOST}</p></body></html>'.replace('{HOST}', os.uname().nodename))
os.chdir('/tmp/www')
print(f'HTTP server listening on 0.0.0.0:{{PORT}}', flush=True)
HTTPServer(('0.0.0.0', PORT), SimpleHTTPRequestHandler).serve_forever()
"""

_SMTP_SCRIPT = """\
#!/usr/bin/env python3
import sys, socket, threading
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 25
LOG  = sys.argv[2] if len(sys.argv) > 2 else '/tmp/smtp.log'
def handle(conn):
    with open(LOG, 'a') as log:
        conn.send(b'220 ISP-emulator SMTP Server\\r\\n')
        data = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk: break
            data += chunk
            while b'\\r\\n' in data:
                line, data = data.split(b'\\r\\n', 1)
                cmd = line.decode('utf-8','ignore').strip().upper()
                log.write(cmd + '\\n'); log.flush()
                if cmd.startswith('EHLO') or cmd.startswith('HELO'):
                    conn.send(b'250 Hello\\r\\n')
                elif cmd.startswith('MAIL'): conn.send(b'250 OK\\r\\n')
                elif cmd.startswith('RCPT'): conn.send(b'250 OK\\r\\n')
                elif cmd == 'DATA': conn.send(b'354 Start input; end with <CRLF>.<CRLF>\\r\\n')
                elif cmd == '.':   conn.send(b'250 Message accepted\\r\\n')
                elif cmd in ('QUIT','RSET'): conn.send(b'221 Bye\\r\\n'); conn.close(); return
    conn.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT)); s.listen(10)
print(f'SMTP listening on 0.0.0.0:{PORT}', flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
"""

_FTP_SCRIPT = """\
#!/usr/bin/env python3
import sys, socket, threading, os
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 21
os.makedirs('/tmp/ftp', exist_ok=True)
def handle(conn, addr):
    data_srv = None
    conn.send(b'220 ISP-emulator FTP Server\\r\\n')
    while True:
        try:
            data = conn.recv(1024)
        except Exception:
            break
        if not data:
            break
        cmd = data.decode('utf-8', 'ignore').strip()
        verb = cmd.split(' ')[0].upper()
        if verb == 'USER':   conn.send(b'331 Password required\\r\\n')
        elif verb == 'PASS': conn.send(b'230 Logged in\\r\\n')
        elif verb == 'SYST': conn.send(b'215 UNIX Type: L8\\r\\n')
        elif verb == 'FEAT': conn.send(b'211-Features:\\r\\n211 End\\r\\n')
        elif verb == 'PWD':  conn.send(b'257 "/" is current dir\\r\\n')
        elif verb == 'TYPE': conn.send(b'200 OK\\r\\n')
        elif verb == 'PASV':
            if data_srv:
                try: data_srv.close()
                except Exception: pass
            data_srv = socket.socket()
            data_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            data_srv.bind(('0.0.0.0', 0))
            data_srv.listen(1)
            data_srv.settimeout(30)
            _, dport = data_srv.getsockname()
            ip = conn.getsockname()[0].replace('.', ',')
            p1, p2 = dport >> 8, dport & 0xff
            conn.send(f'227 Entering Passive Mode ({ip},{p1},{p2})\\r\\n'.encode())
        elif verb == 'STOR':
            if data_srv:
                conn.send(b'150 Opening data connection\\r\\n')
                try:
                    dc, _ = data_srv.accept()
                    while dc.recv(65536): pass
                    dc.close()
                    conn.send(b'226 Transfer complete\\r\\n')
                except Exception:
                    conn.send(b'425 Cannot open data connection\\r\\n')
                finally:
                    data_srv.close()
                    data_srv = None
            else:
                conn.send(b'425 Use PASV first\\r\\n')
        elif verb == 'LIST': conn.send(b'150 Here comes\\r\\n226 Done\\r\\n')
        elif verb == 'QUIT': conn.send(b'221 Bye\\r\\n'); break
        else: conn.send(b'200 OK\\r\\n')
    conn.close()
    if data_srv:
        try: data_srv.close()
        except Exception: pass
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT)); s.listen(10)
print(f'FTP listening on 0.0.0.0:{PORT}', flush=True)
while True:
    c, a = s.accept()
    threading.Thread(target=handle, args=(c, a), daemon=True).start()
"""

_DNS_SCRIPT = """\
#!/usr/bin/env python3
import sys, socket
PORT   = int(sys.argv[1]) if len(sys.argv) > 1 else 53
REPLY_IP = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
def make_reply(data):
    tid   = data[:2]
    flags = b'\\x81\\x80'
    qdcnt = data[4:6]
    ancnt = b'\\x00\\x01'
    head  = tid + flags + qdcnt + ancnt + b'\\x00\\x00\\x00\\x00'
    quest = data[12:]
    ans   = (b'\\xc0\\x0c' + b'\\x00\\x01' + b'\\x00\\x01'
             + b'\\x00\\x00\\x00\\x3c' + b'\\x00\\x04'
             + bytes(int(x) for x in REPLY_IP.split('.')))
    return head + quest + ans
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT))
print(f'DNS listening on 0.0.0.0:{PORT} (always replies {REPLY_IP})', flush=True)
while True:
    try:
        data, addr = s.recvfrom(512)
        s.sendto(make_reply(data), addr)
    except Exception: pass
"""

_ECHO_SCRIPT = """\
#!/usr/bin/env python3
import sys, socket, threading
PORT  = int(sys.argv[1]) if len(sys.argv) > 1 else 7
PROTO = sys.argv[2] if len(sys.argv) > 2 else 'tcp'
if PROTO == 'udp':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', PORT))
    print(f'Echo-UDP listening on 0.0.0.0:{PORT}', flush=True)
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(d, a)
else:
    def handle(c):
        while True:
            d = c.recv(4096)
            if not d: break
            c.send(d)
        c.close()
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', PORT)); s.listen(10)
    print(f'Echo-TCP listening on 0.0.0.0:{PORT}', flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
"""

_CUSTOM_TCP_SCRIPT = """\
#!/usr/bin/env python3
import sys, socket, threading
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
MSG  = sys.argv[2] if len(sys.argv) > 2 else 'ISP-emulator custom TCP'
def handle(c):
    c.send((MSG + '\\n').encode())
    c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT)); s.listen(10)
print(f'Custom-TCP on 0.0.0.0:{PORT}', flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
"""

_CUSTOM_UDP_SCRIPT = """\
#!/usr/bin/env python3
import sys, socket
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
MSG  = sys.argv[2] if len(sys.argv) > 2 else 'ISP-emulator custom UDP'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT))
print(f'Custom-UDP on 0.0.0.0:{PORT}', flush=True)
while True:
    _, addr = s.recvfrom(65535)
    s.sendto(MSG.encode(), addr)
"""

_SSH_SCRIPT = """\
#!/usr/bin/env python3
import sys, socket, threading
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 22
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\\r\\n"
def handle(conn):
    try:
        conn.send(BANNER.encode())
        conn.recv(256)  # absorb client version string
    except Exception: pass
    finally: conn.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT)); s.listen(10)
print(f'SSH-banner server on 0.0.0.0:{PORT}', flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
"""

_SCRIPTS: Dict[str, str] = {
    "http":       _HTTP_SCRIPT,
    "https":      _HTTP_SCRIPT,   # same server, different port
    "ftp":        _FTP_SCRIPT,
    "smtp":       _SMTP_SCRIPT,
    "dns":        _DNS_SCRIPT,
    "ssh":        _SSH_SCRIPT,
    "echo":       _ECHO_SCRIPT,
    "custom_tcp": _CUSTOM_TCP_SCRIPT,
    "custom_udp": _CUSTOM_UDP_SCRIPT,
}


class ServiceManager:
    """Deploy and track services on Mininet hosts."""

    def __init__(
        self,
        net: "Mininet",
        config: TopologyConfig,
        registry: Optional[ServiceRegistry] = None,
    ) -> None:
        self.net = net
        self.config = config
        self.registry = registry or ServiceRegistry()

    # ----------------------------------------------------------------- public

    def deploy_all(self) -> None:
        """Deploy all services declared in config according to deployment mode."""
        mode = self.config.deployment.mode
        logger.info("Service deployment mode: %s", mode)

        if mode == "manual":
            logger.info(
                "Manual mode: skipping auto-deployment. "
                "Start services yourself in the Mininet CLI."
            )
            return

        for svc in self.config.services:
            try:
                self._deploy_one(svc)
            except Exception as exc:
                logger.error("Service deploy failed %s/%s: %s", svc.host, svc.type, exc)

        logger.info("Service deployment complete")

    def stop_all(self) -> None:
        """Kill all managed service processes."""
        for node_cfg in self.config.nodes:
            if node_cfg.is_switch():
                continue
            node = self.net[node_cfg.name]
            node.cmd("pkill -f 'python3 /tmp/svc_' 2>/dev/null || true")

    # --------------------------------------------------------------- internals

    def _deploy_one(self, svc: ServiceConfig) -> None:
        port = effective_port(svc.type, svc.port)
        node = self.net[svc.host]

        if svc.type == "sqlite":
            # SQLite service without API server is a no-op here;
            # the DatabaseManager handles it.
            logger.debug("sqlite service on %s is managed by DatabaseManager", svc.host)
            self.registry.register(svc.host, svc.type, port)
            return

        if svc.type not in _SCRIPTS:
            logger.warning("Unknown service type %r on %s — skipping", svc.type, svc.host)
            return

        script_path = f"/tmp/svc_{svc.host}_{svc.type}_{port}.py"
        with open(script_path, "w") as fh:
            fh.write(_SCRIPTS[svc.type])
        os.chmod(script_path, 0o755)

        # Extra args depending on service type
        extra = ""
        if svc.type == "dns":
            extra = f" {svc.options.get('reply_ip', '127.0.0.1')}"
        elif svc.type in ("custom_tcp", "custom_udp"):
            msg = svc.options.get("message", "ISP-emulator")
            extra = f" '{msg}'"
        elif svc.type in ("echo",):
            proto = svc.options.get("proto", "tcp")
            extra = f" {proto}"

        log_path = f"/tmp/svc_{svc.host}_{svc.type}_{port}.log"
        node.cmd(
            f"python3 {script_path} {port}{extra} > {log_path} 2>&1 &"
        )
        time.sleep(0.3)

        pid = self._get_pid(node, port)
        status = "running" if pid else "failed"
        inst = self.registry.register(svc.host, svc.type, port, pid)
        inst.status = status

        if status == "running":
            logger.info("Service UP: %s/%s :%d pid=%s", svc.host, svc.type, port, pid)
        else:
            logger.warning(
                "Service may have failed: %s/%s :%d — check %s",
                svc.host, svc.type, port, log_path,
            )

    @staticmethod
    def _get_pid(node, port: int) -> str:
        """Return PID of process listening on port, or empty string."""
        out = node.cmd(f"ss -tlnp sport = :{port} 2>/dev/null").strip()
        # ss output: "LISTEN 0 1 0.0.0.0:8080 ... pid=1234,..."
        for line in out.splitlines():
            if f":{port}" in line and "pid=" in line:
                try:
                    return line.split("pid=")[1].split(",")[0].split(")")[0]
                except IndexError:
                    pass
        # fallback: try pgrep
        pg = node.cmd(f"pgrep -f 'svc_{node.name}' 2>/dev/null").strip()
        return pg.split("\n")[0] if pg else ""
