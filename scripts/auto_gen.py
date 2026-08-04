#!/usr/bin/env python3
"""
scripts/auto_gen.py — CYBER-PULSE Experiment Automation Runner (v3)

Complete redesign. Uses pexpect to drive the Mininet interactive CLI exactly
as a human operator would. Every experiment runs in complete isolation:

    mn -c  →  spawn topology --cli  →  command sequence  →  exit  →  mn -c

Why the previous design failed
-------------------------------
1. Session reuse: one Mininet session served all combos for a topology. Any
   state from a previous combo (VPN mode, NPC threads, inject, TC rules)
   leaked into the next experiment.

2. Missing "apply tc": the manual workflow requires an explicit "apply tc"
   before NPC start. The old code skipped it and relied on capture start's
   auto-apply, which runs after NPC has already been generating traffic on
   unconditioned links.

   Verified from ISPCli.do_apply() and do_capture():
     - apply tc is a no-op when the topology has no traffic_control config
       (safe to call unconditionally).
     - apply tc is blocked once capture is running, so it must come before
       capture start.
     - capture start only auto-applies TC if no prior TC profile was set,
       so calling apply tc first ensures the explicit profile is used.

3. Fragile stdin/select driver: select() + os.read() on subprocess stdout
   is not designed for PTY-based interactive terminal applications. It cannot
   synchronise on prompt state — it only observes bytes. This caused BrokenPipe
   errors, NPC restart failures, and timing races.

4. mn -c only at topology boundaries: not between individual experiments, so
   stale OVS bridges and iptables rules accumulated across combos.

5. Wait semantics conflated: the configured wait duration is the per-experiment
   baseline capture window. The old code applied it as an inter-combo delay
   within the shared session — wrong in both meaning and placement.

6. Progress key incomplete: wait was not a dimension in the key. Changing the
   wait configuration between runs silently reused stale progress entries.

Design principles
-----------------
This automation is part of the scientific data-generation pipeline, not a
convenience script. Each experiment produces labeled network traffic that
becomes CNN training data. Contamination from leaked runtime state, timing
races, or inconsistent execution introduces bias and noise into the dataset.
Correctness, reproducibility, and experiment isolation matter more than speed.

Usage (requires root for Mininet):
    sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml
    sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml --repeat 5
    sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml --fixed-time 15
    sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml --min-time 10 --max-time 30
    sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml --dry-run
    sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml --resume
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, fields as dc_fields
from itertools import product
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required.  pip install pyyaml")
    sys.exit(1)

try:
    import pexpect
except ImportError:
    print("ERROR: pexpect required.  pip install pexpect")
    sys.exit(1)

_SCRIPTS_DIR = Path(__file__).resolve().parent
_ROOT        = _SCRIPTS_DIR.parent

_PROGRESS_FILE = _ROOT / ".auto_gen_progress.json"
_SCHEMA_FILE   = _ROOT / "dataset" / "schema.json"

# Mininet CLI prompt — matched as a literal string via expect_exact()
_CLI_PROMPT = "mininet> "

# Timing constants (preregistered experiment protocol — do not change after freeze)
_NPC_WARMUP_S           = 10   # let NPC threads prime links before capture starts
_PRE_ACTION_S           = 5    # capture window before exfil/baseline divergence
_STARTUP_TIMEOUT_S      = 240  # topology boot: VPN + DB deploy can take up to 4 min
_CMD_TIMEOUT_S          = 120  # typical CLI command completes well under 2 min
_EXFIL_TIMEOUT_S        = 60   # exfil: curl --max-time 10 + iptables overhead
_CAPTURE_STOP_TIMEOUT_S = 300  # capture stop: merge + feature selection + CSV pipeline
_EXIT_TIMEOUT_S         = 90   # topology teardown after exit command


# ──────────────────────────────────────────────────── data models ─────────


@dataclass
class ExperimentConfig:
    topologies: list[str]
    repeat:     int
    vpn:        list[str]
    npc:        list[str]
    inject:     list[str]
    exfil:      list[str]

    @property
    def total_runs(self) -> int:
        return (
            len(self.topologies)
            * len(self.vpn)
            * len(self.npc)
            * len(self.inject)
            * len(self.exfil)
            * self.repeat
        )


@dataclass
class Combo:
    """One unique experiment condition.

    Every field is a first-class experiment dimension and participates in the
    progress key. The key is derived automatically from dc_fields() so that
    adding a new YAML dimension requires only adding a field here and including
    it in build_combos() — no manual key editing needed.
    """
    topology: str
    vpn:      str
    npc:      str
    inject:   str
    exfil:    str
    run:      int   # 1-indexed within this combo's repeat block

    def key(self) -> str:
        """Stable identifier — auto-derived from every Combo field in definition order."""
        parts = []
        for f in dc_fields(self):
            val = getattr(self, f.name)
            if f.name == "topology":
                val = Path(val).stem
            parts.append(f"{f.name}={val}")
        return "|".join(parts)

    def pretty(self) -> str:
        topo = Path(self.topology).stem
        return (
            f"topo={topo:<30} vpn={self.vpn:<4} npc={self.npc:<7} "
            f"inject={self.inject:<4} exfil={self.exfil:<4} run={self.run}"
        )


# ─────────────────────────── YAML loader without bool coercion ────


class _NoAutoBoolLoader(yaml.SafeLoader):
    """SafeLoader that keeps on/off/true/false as plain strings.

    PyYAML normally converts on/off/yes/no/true/false to Python booleans,
    which breaks parameter lists like `vpn: [on, off]`.
    """


_NoAutoBoolLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers
          if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


# ────────────────────────────── YAML loading and validation ────────


class ConfigError(ValueError):
    pass


def _require_str_list(data: dict, key: str) -> list[str]:
    val = data.get(key)
    if not isinstance(val, list) or not val:
        raise ConfigError(f"'{key}' must be a non-empty list")
    return [str(v) for v in val]


def load_yaml_config(config_path: Path) -> ExperimentConfig:
    """Load and validate auto-gen.yaml. Raises ConfigError on violations."""
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as fh:
        try:
            data = yaml.load(fh, Loader=_NoAutoBoolLoader)
        except yaml.YAMLError as exc:
            raise ConfigError(f"YAML parse error: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Config file must be a YAML mapping")

    topologies = _require_str_list(data, "selected")
    for t in topologies:
        p = _ROOT / t
        if not p.exists():
            raise ConfigError(f"Topology not found: {p}")

    repeat_raw = data.get("repeat")
    if isinstance(repeat_raw, list):
        raise ConfigError("'repeat' must be a scalar integer, not a list")
    if not isinstance(repeat_raw, int) or repeat_raw < 1:
        raise ConfigError("'repeat' must be an integer >= 1")

    exfil = _require_str_list(data, "exfil")
    for v in exfil:
        if v not in ("on", "off"):
            raise ConfigError(f"'exfil' values must be 'on' or 'off', got {v!r}")

    return ExperimentConfig(
        topologies=topologies,
        repeat=repeat_raw,
        vpn=_require_str_list(data, "vpn"),
        npc=_require_str_list(data, "npc"),
        inject=_require_str_list(data, "inject"),
        exfil=exfil,
    )


# ──────────────────────────────────── CLI argument parsing ─────────


def _warn(msg: str) -> None:
    print(f"\nWARNING\n{msg}\n", flush=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="auto_gen.py",
        description="CYBER-PULSE automation runner — pexpect-based Mininet CLI driver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 scripts/auto_gen.py
  sudo python3 scripts/auto_gen.py --repeat 5
  sudo python3 scripts/auto_gen.py --dry-run
  sudo python3 scripts/auto_gen.py --resume
  sudo python3 scripts/auto_gen.py --config /path/to/other.yaml
""",
    )
    p.add_argument(
        "--config",
        default=str(_ROOT / "configs" / "auto-gen.yaml"),
        metavar="FILE",
        help="Path to auto-gen.yaml (default: configs/auto-gen.yaml)",
    )
    p.add_argument("--repeat",  type=int, metavar="N",
                   help="Override repeat count (>= 1)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print plan and exit — no Mininet started")
    p.add_argument("--resume",  action="store_true",
                   help="Skip already-completed combos from a previous run")
    return p


def _resolve_repeat(args: argparse.Namespace, yaml_repeat: int) -> int:
    if args.repeat is None:
        return yaml_repeat
    if args.repeat < 1:
        _warn("Repeat must be >= 1.\n\nUsing repeat from auto-gen.yaml.")
        return yaml_repeat
    return args.repeat


def resolve_config(args: argparse.Namespace, yaml_cfg: ExperimentConfig) -> ExperimentConfig:
    """Merge CLI overrides into yaml_cfg. Priority: CLI > YAML > defaults."""
    return ExperimentConfig(
        topologies=yaml_cfg.topologies,
        repeat=_resolve_repeat(args, yaml_cfg.repeat),
        vpn=yaml_cfg.vpn,
        npc=yaml_cfg.npc,
        inject=yaml_cfg.inject,
        exfil=yaml_cfg.exfil,
    )


def print_summary(cfg: ExperimentConfig) -> None:
    border = "=" * 32
    print(f"\n{border}")
    print("Experiment Configuration")
    print(border)
    print()
    print(f"Topologies : {len(cfg.topologies)}")
    print(f"Repeat     : {cfg.repeat}")
    print()
    print(f"VPN        : {'/'.join(cfg.vpn)}")
    print(f"NPC        : {', '.join(cfg.npc)}")
    print(f"Inject     : {'/'.join(cfg.inject)}")
    print(f"Exfil      : {'/'.join(cfg.exfil)}")
    print()
    print(f"Total Runs : {cfg.total_runs}")
    print(f"{border}\n")


# ──────────────────────────────────────── combo generation ────────────


def build_combos(cfg: ExperimentConfig) -> list[Combo]:
    """Generate the full Cartesian product × repeat.

    Every ExperimentConfig list field is a Cartesian dimension. To add a new
    YAML dimension: add a list[str] field to ExperimentConfig, add a field to
    Combo, and include it in the product() call below. The key and total_runs
    update automatically.
    """
    combos: list[Combo] = []
    for topo in cfg.topologies:
        for vpn, npc, inject, exfil, run in product(
            cfg.vpn,
            cfg.npc,
            cfg.inject,
            cfg.exfil,
            range(1, cfg.repeat + 1),
        ):
            combos.append(Combo(
                topology=topo,
                vpn=vpn,
                npc=npc,
                inject=inject,
                exfil=exfil,
                run=run,
            ))
    return combos


# ───────────────────────────── resume / progress tracking ─────────────


def load_progress() -> set[str]:
    if not _PROGRESS_FILE.exists():
        return set()
    try:
        with _PROGRESS_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def save_progress(done: set[str]) -> None:
    try:
        with _PROGRESS_FILE.open("w", encoding="utf-8") as fh:
            json.dump(sorted(done), fh, indent=2)
    except OSError as exc:
        print(f"  WARNING: could not save progress: {exc}", flush=True)


# ──────────────────────────────────────────── Mininet cleanup ─────────────


def _mn_cleanup() -> None:
    """Wipe all Mininet/OVS/iptables state. Called before and after each experiment."""
    print("\n[cleanup] sudo mn -c", flush=True)
    try:
        subprocess.run(
            ["sudo", "mn", "-c"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45,
            cwd=str(_ROOT),
        )
    except Exception as exc:
        print(f"  WARNING: mn -c failed: {exc}", flush=True)


# ──────────────────────────── pexpect experiment driver ───────────────────


def _cmd(child: "pexpect.spawn", command: str, timeout: float = _CMD_TIMEOUT_S) -> None:
    """Send one command and wait for the prompt to confirm completion."""
    print(f"\n>>> {command}", flush=True)
    child.sendline(command)
    child.expect_exact(_CLI_PROMPT, timeout=timeout)


def run_experiment(combo: Combo) -> bool:
    """
    Execute one experiment in complete isolation.

    Lifecycle:
        mn -c
        spawn: sudo python3 network/topology.py <topology> --cli
        wait for initial "mininet> " prompt (topology fully initialised)
        manual workflow (verified against ISPCli source):
            vpn on|off
            apply tc          <- verified: safe no-op if topology has no TC config;
                                 must precede npc start so TC conditions are active
                                 for all NPC traffic; blocked after capture start
            npc start --intensity <level>
            inject on|off
            [sleep _NPC_WARMUP_S]
            capture start
            [sleep _PRE_ACTION_S]
            exfil on          — TOS-marked HTTP GET to DB (label=1)
            OR
            exfil off         — plain HTTP GET to DB     (label=0)
            capture stop      (triggers merge + CSV pipeline if automatic: true)
            npc stop
            exit
        wait for EOF (topology process fully terminated)
        mn -c

    Returns True if all commands completed without timeout or unexpected EOF.
    """
    _mn_cleanup()

    child: Optional["pexpect.spawn"] = None

    try:
        topology_path = str(_ROOT / combo.topology)
        cmd = f"sudo python3 {_ROOT / 'network' / 'topology.py'} {topology_path} --cli"
        print(f"\n[launch] {cmd}", flush=True)

        child = pexpect.spawn(
            cmd,
            timeout=_STARTUP_TIMEOUT_S,
            encoding="utf-8",
            codec_errors="replace",
            logfile=sys.stdout,
            cwd=str(_ROOT),
        )

        # Wait for initial prompt — topology fully initialised
        child.expect_exact(_CLI_PROMPT, timeout=_STARTUP_TIMEOUT_S)

        # ── 1. VPN ────────────────────────────────────────────────────────────
        _cmd(child, f"vpn {combo.vpn}")

        # ── 2. Traffic Control ────────────────────────────────────────────────
        _cmd(child, "apply tc")

        # ── 3. Background NPC traffic ─────────────────────────────────────────
        _cmd(child, f"npc start --intensity {combo.npc}")

        # ── 4. Timing protocol ────────────────────────────────────────────────
        _cmd(child, f"inject {combo.inject}")

        # NPC warmup: threads prime all links before capture starts
        print(f"\n  [warmup] {_NPC_WARMUP_S}s ...", flush=True)
        time.sleep(_NPC_WARMUP_S)

        # ── 5. Start capture ──────────────────────────────────────────────────
        _cmd(child, "capture start")

        # Pre-action window: baseline traffic before exfil/label divergence
        print(f"  [pre-action] {_PRE_ACTION_S}s ...", flush=True)
        time.sleep(_PRE_ACTION_S)

        # ── 6. Exfil on=TOS-marked (label=1), off=plain (label=0) ───────────────
        _cmd(child, f"exfil {combo.exfil}", timeout=_EXFIL_TIMEOUT_S)

        # ── 7. Stop capture — triggers merge + CSV pipeline ───────────────────
        # capture stop internally calls npc_manager.stop() (capture_manager.py:183)
        _cmd(child, "capture stop", timeout=_CAPTURE_STOP_TIMEOUT_S)

        # ── 8. Exit topology ──────────────────────────────────────────────────
        print(f"\n>>> exit", flush=True)
        child.sendline("exit")
        child.expect(pexpect.EOF, timeout=_EXIT_TIMEOUT_S)

        return True

    except pexpect.TIMEOUT:
        before = getattr(child, "before", "") or ""
        print(
            f"\n  ERROR [timeout]: '{_CLI_PROMPT}' not seen within timeout.\n"
            f"  Last output: {before[-1000:]}",
            flush=True,
        )
        return False

    except pexpect.EOF:
        before = getattr(child, "before", "") or ""
        print(
            f"\n  ERROR [EOF]: topology process exited unexpectedly.\n"
            f"  Last output: {before[-1000:]}",
            flush=True,
        )
        return False

    except Exception as exc:
        print(f"\n  ERROR: {exc}", flush=True)
        return False

    finally:
        if child is not None and child.isalive():
            try:
                child.terminate(force=True)
            except Exception:
                pass
        _mn_cleanup()


# ─────────────────────────── schema annotation ───────────────────────────────


def _annotate_latest_schema_entry(combo: Combo) -> None:
    """Stamp the newest schema.json entry with the full experiment combo.

    Experiments run sequentially (one at a time), so the last entry is always
    the one written by the experiment that just completed.

    Fields written under 'experiment' cover ALL combos — including sessions
    where timing_protocol is empty (inject=off) which carry no other record
    of the vpn/npc/inject/exfil settings used.
    """
    if not _SCHEMA_FILE.exists():
        print("  WARNING: schema.json not found — combo not annotated.", flush=True)
        return
    try:
        with _SCHEMA_FILE.open("r", encoding="utf-8") as fh:
            records = json.load(fh)
        if not isinstance(records, list) or not records:
            return
        last = records[-1]
        if not isinstance(last, dict):
            return
        last["experiment"] = {
            "vpn":    combo.vpn,
            "npc":    combo.npc,
            "inject": combo.inject,
            "exfil":  combo.exfil,
            "run":    combo.run,
        }
        raw = json.dumps(records, indent=2)
        compacted = re.sub(
            r'"rhythm":\s*(\[[^\]]*\])',
            lambda m: '"rhythm": [' + ",".join(re.findall(r"\d+", m.group(1))) + "]",
            raw,
            flags=re.DOTALL,
        )
        with _SCHEMA_FILE.open("w", encoding="utf-8") as fh:
            fh.write(compacted)
    except Exception as exc:
        print(f"  WARNING: schema annotation failed: {exc}", flush=True)


# ──────────────────────────────────────────────────────────── main ────────────


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    config_path = Path(args.config)

    try:
        yaml_cfg = load_yaml_config(config_path)
    except ConfigError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    cfg = resolve_config(args, yaml_cfg)
    print_summary(cfg)

    combos = build_combos(cfg)
    total  = len(combos)

    if args.dry_run:
        print(f"DRY RUN — {total} combos planned:\n")
        for c in combos:
            print(f"  {c.pretty()}")
        print()
        return

    # Resume: load completed keys from previous run
    done: set[str] = set()
    if args.resume:
        done = load_progress()
        skipped = sum(1 for c in combos if c.key() in done)
        if skipped:
            print(f"RESUME: skipping {skipped}/{total} already-completed combos.", flush=True)

    pending = [c for c in combos if c.key() not in done]

    grand_ok   = 0
    grand_fail = 0

    for idx, combo in enumerate(pending, 1):
        print(
            f"\n{'#' * 60}\n"
            f"# [{idx}/{len(pending)}] {combo.pretty()}\n"
            f"{'#' * 60}",
            flush=True,
        )

        success = run_experiment(combo)

        if success:
            _annotate_latest_schema_entry(combo)
            grand_ok += 1
            done.add(combo.key())
            save_progress(done)
        else:
            grand_fail += 1

    border  = "=" * 32
    skipped = total - len(pending)
    print(f"\n{border}")
    print("BATCH COMPLETE")
    print(f"{border}")
    print(f"  Total     : {total}")
    print(f"  Skipped   : {skipped}")
    print(f"  Completed : {grand_ok}")
    print(f"  Failed    : {grand_fail}")
    print(f"{border}\n")

    if grand_fail == 0 and _PROGRESS_FILE.exists():
        _PROGRESS_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
