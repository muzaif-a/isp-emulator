"""
NPC behavior implementations.

Each function executes one traffic unit inside a Mininet host namespace
via node.cmd(). Distributions from CAIDA measurements.

Behaviors:
  http      — curl GET to web1:8080          lognormal(7,2) KB
  dns       — dig query to dns1:53           expovariate(1/8) s
  db_query  — curl GET to db1:9090           expovariate(1/5) s
  smtp      — smtplib send to web1:25        lognormal(8,3) KB
  ftp       — ftplib upload to ftp1:21       uniform(0.1,5) MB
  bulk      — iperf3 UDP to peer NPC         2–8 Mbps for 5 s
  echo      — TCP echo to h1:7               uniform(8,512) B
  idle      — no-op (inter-arrival handles sleep)
"""

import math
import random


def _lognormal_bytes(mu: float, sigma: float) -> int:
    return max(512, int(math.exp(random.gauss(mu, sigma))))


def http(node, web1_ip: str, port: int = 8080) -> None:
    """HTTP GET — lognormal(7,2) KB response body."""
    node.cmd(
        f"curl -sf --max-time 10 http://{web1_ip}:{port}/ "
        f"-o /dev/null 2>/dev/null || true"
    )


def dns(node, dns1_ip: str, port: int = 53, domains=None) -> None:
    """DNS A query — expovariate(1/8) s inter-arrival."""
    if not domains:
        return
    domain = random.choice(domains)
    node.cmd(
        f"dig @{dns1_ip} -p {port} {domain} +time=3 +tries=1 "
        f"> /dev/null 2>&1 || true"
    )


def db_query(node, db1_ip: str, port: int = 9090, endpoints=None) -> None:
    """DB REST GET — expovariate(1/5) s inter-arrival."""
    if not endpoints:
        return
    ep = random.choice(endpoints)
    node.cmd(
        f"curl -sf --max-time 10 http://{db1_ip}:{port}{ep} "
        f"-o /dev/null 2>/dev/null || true"
    )


def smtp(node, web1_ip: str, port: int = 25,
         smtp_from: str = None, smtp_to: str = None) -> None:
    """SMTP send — lognormal(8,3) KB body — uniform(30,300) s inter-arrival."""
    if not smtp_from or not smtp_to:
        return
    body_size = min(_lognormal_bytes(8, 3), 65536)
    script = (
        "python3 -c \""
        "import smtplib;"
        f"s=smtplib.SMTP('{web1_ip}',{port},timeout=10);"
        f"s.sendmail('{smtp_from}','{smtp_to}',"
        f"'Subject: npc\\n\\n{'X'*body_size}');"
        "s.quit()"
        "\" 2>/dev/null || true"
    )
    node.cmd(script)


def ftp(node, ftp1_ip: str, port: int = 21) -> None:
    """FTP store — uniform(0.1,5) MB — uniform(60,600) s inter-arrival."""
    size_bytes = int(random.uniform(0.1, 5.0) * 1024 * 1024)
    script = (
        "python3 -c \""
        "import ftplib,io;"
        f"f=ftplib.FTP();"
        f"f.connect('{ftp1_ip}',{port},timeout=15);"
        "f.login('anonymous','npc@local');"
        f"f.storbinary('STOR npc.bin',io.BytesIO(b'A'*{size_bytes}));"
        "f.quit()"
        "\" 2>/dev/null || true"
    )
    node.cmd(script)


def bulk(node, peer_ip: str, port: int = 5201) -> None:
    """iperf3 UDP bulk — 2–8 Mbps sustained for 5 s."""
    bw = random.uniform(2.0, 8.0)
    node.cmd(
        f"iperf3 -c {peer_ip} -u -b {bw:.1f}M -t 5 -p {port} "
        f"--connect-timeout 3000 > /dev/null 2>&1 || true"
    )


def echo(node, echo_ip: str, port: int = 7) -> None:
    """TCP echo — uniform(8,512) B payload, expovariate(1/20) s inter-arrival."""
    size = random.randint(8, 512)
    script = (
        "python3 -c \""
        "import socket;"
        f"s=socket.socket();"
        f"s.settimeout(5);"
        f"s.connect(('{echo_ip}',{port}));"
        f"s.sendall(b'E'*{size});"
        f"s.recv({size});"
        "s.close()"
        "\" 2>/dev/null || true"
    )
    node.cmd(script)


def idle(node) -> None:
    """No-op — NPC loop handles inter-arrival sleep via stop_event.wait()."""
    pass
