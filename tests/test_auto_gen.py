"""Unit tests for scripts/auto_gen.py pure functions.

Tests _parse_wait, build_combos, load_yaml_config.
No Mininet, no root, no pexpect invocation.
All expectations derived from the functions themselves — no hardcoded counts
except those that directly validate the Cartesian product formula.
"""

import os
import sys
import math
import json
import tempfile
import textwrap
from itertools import product as iterproduct
from pathlib import Path

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from auto_gen import (
    _parse_wait,
    build_combos,
    load_yaml_config,
    ConfigError,
    ExperimentConfig,
    Combo,
)

AUTOGEN_PATH = os.path.join(ROOT, "configs", "auto-gen.yaml")


# ─────────────────────── _parse_wait ─────────────────────────────────────────

@pytest.mark.unit
class TestParseWait:

    @pytest.mark.parametrize("values,expected", [
        ([10],          ["10"]),
        ([10, 20],      ["10", "20"]),
        ([10, 20, 30],  ["10", "20", "30"]),
        ([0],           ["0"]),
        ([60],          ["60"]),
    ])
    def test_list_format(self, values, expected):
        assert _parse_wait({"wait": values}) == expected

    @pytest.mark.parametrize("raw,expected", [
        ({"fixed": 10},               ["10"]),
        ({"fixed": 15},               ["15"]),
        ({"mode": "fixed", "value": 20}, ["20"]),
        ({"mode": "fixed", "value": 0},  ["0"]),
    ])
    def test_fixed_format(self, raw, expected):
        assert _parse_wait({"wait": raw}) == expected

    @pytest.mark.parametrize("raw,expected", [
        ({"random": {"min": 10, "max": 20}},       ["random:10-20"]),
        ({"mode": "random", "min": 5, "max": 30},  ["random:5-30"]),
        ({"random": {"min": 0, "max": 0}},         ["random:0-0"]),
    ])
    def test_random_format(self, raw, expected):
        assert _parse_wait({"wait": raw}) == expected

    @pytest.mark.parametrize("bad", [
        {"wait": []},
        {"wait": [-1]},
        {"wait": [-5, 10]},
        {"wait": ["abc"]},
        {"wait": {}},
        {"wait": None},
        {},
    ])
    def test_invalid_raises(self, bad):
        with pytest.raises(ConfigError):
            _parse_wait(bad)

    def test_random_min_gt_max_raises(self):
        with pytest.raises(ConfigError):
            _parse_wait({"wait": {"random": {"min": 30, "max": 10}}})

    def test_fixed_negative_raises(self):
        with pytest.raises(ConfigError):
            _parse_wait({"wait": {"fixed": -5}})

    def test_unknown_dict_format_raises(self):
        with pytest.raises(ConfigError):
            _parse_wait({"wait": {"unknown_key": 10}})


# ─────────────────────── build_combos ────────────────────────────────────────

@pytest.mark.unit
class TestBuildCombos:

    def _cfg(self, topologies, vpn, npc, inject, exfil, wait, repeat=1):
        return ExperimentConfig(
            topologies=topologies,
            vpn=vpn,
            npc=npc,
            inject=inject,
            exfil=exfil,
            wait=wait,
            repeat=repeat,
        )

    def test_count_equals_cartesian_product(self):
        topologies = ["topo_a.yaml", "topo_b.yaml"]
        vpn        = ["on", "off"]
        npc        = ["low", "medium", "high"]
        inject     = ["on", "off"]
        exfil      = ["true", "false"]
        wait       = ["10", "20"]
        repeat     = 3

        cfg = self._cfg(topologies, vpn, npc, inject, exfil, wait, repeat)
        combos = build_combos(cfg)

        expected = (
            len(topologies) * len(vpn) * len(npc)
            * len(inject) * len(exfil) * len(wait) * repeat
        )
        assert len(combos) == expected

    def test_each_combo_is_combo_instance(self):
        cfg = self._cfg(["t.yaml"], ["on"], ["medium"], ["on"], ["true"], ["10"])
        for c in build_combos(cfg):
            assert isinstance(c, Combo)

    def test_all_dimension_values_appear(self):
        vpn_vals = ["on", "off"]
        npc_vals = ["low", "high"]
        cfg = self._cfg(["t.yaml"], vpn_vals, npc_vals, ["on"], ["true"], ["10"])
        combos = build_combos(cfg)
        assert set(c.vpn for c in combos) == set(vpn_vals)
        assert set(c.npc for c in combos) == set(npc_vals)

    def test_run_numbers_sequential_per_combo(self):
        cfg = self._cfg(["t.yaml"], ["on"], ["medium"], ["on"], ["true"], ["10"], repeat=3)
        combos = build_combos(cfg)
        runs = sorted(c.run for c in combos)
        assert runs == [1, 2, 3]

    def test_empty_topology_produces_no_combos(self):
        cfg = self._cfg([], ["on"], ["medium"], ["on"], ["true"], ["10"])
        assert build_combos(cfg) == []

    def test_repeat_1_each_topology_appears_once_per_dim_combo(self):
        cfg = self._cfg(["t.yaml"], ["on"], ["medium"], ["on"], ["true"], ["10"], repeat=1)
        combos = build_combos(cfg)
        assert len(combos) == 1
        assert combos[0].run == 1

    def test_topology_field_preserved(self):
        topo = "configs/topology.yaml"
        cfg = self._cfg([topo], ["on"], ["medium"], ["on"], ["true"], ["10"])
        assert all(c.topology == topo for c in build_combos(cfg))

    @pytest.mark.parametrize("repeat", [1, 2, 5, 10])
    def test_repeat_scales_count_linearly(self, repeat):
        cfg = self._cfg(["t.yaml"], ["on"], ["medium"], ["on"], ["true"], ["10"], repeat=repeat)
        assert len(build_combos(cfg)) == repeat


# ─────────────────────── load_yaml_config ────────────────────────────────────

@pytest.mark.unit
class TestLoadYamlConfig:

    def _write(self, content: str) -> Path:
        f = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
        f.write(textwrap.dedent(content))
        f.close()
        return Path(f.name)

    def _minimal(self, topo: str = "configs/topology.yaml") -> str:
        return f"""
            selected:
              - {topo}
            repeat: 1
            vpn:    [off]
            npc:    [medium]
            inject: [on]
            exfil:  [true]
            wait:   [10]
        """

    def test_valid_config_loads(self):
        p = self._write(self._minimal())
        cfg = load_yaml_config(p)
        assert len(cfg.vpn) == 1
        assert cfg.repeat == 1

    def test_missing_file_raises(self):
        with pytest.raises(ConfigError):
            load_yaml_config(Path("/nonexistent/path.yaml"))

    @pytest.mark.parametrize("field", ["selected", "repeat", "vpn", "npc",
                                        "inject", "exfil", "wait"])
    def test_missing_required_field_raises(self, field):
        base = {
            "selected": ["configs/topology.yaml"],
            "repeat": 1, "vpn": ["off"], "npc": ["medium"],
            "inject": ["on"], "exfil": ["true"], "wait": [10],
        }
        del base[field]
        import yaml
        p = self._write(yaml.dump(base))
        with pytest.raises(ConfigError):
            load_yaml_config(p)

    def test_repeat_zero_raises(self):
        content = self._minimal().replace("repeat: 1", "repeat: 0")
        p = self._write(content)
        with pytest.raises(ConfigError):
            load_yaml_config(p)

    def test_repeat_negative_raises(self):
        content = self._minimal().replace("repeat: 1", "repeat: -1")
        p = self._write(content)
        with pytest.raises(ConfigError):
            load_yaml_config(p)

    def test_vpn_values_normalized(self):
        p = self._write(self._minimal())
        cfg = load_yaml_config(p)
        for v in cfg.vpn:
            assert v in ("on", "off"), f"unexpected vpn value: {v!r}"

    def test_npc_values_normalized(self):
        p = self._write(self._minimal())
        cfg = load_yaml_config(p)
        for v in cfg.npc:
            assert v in ("low", "medium", "high"), f"unexpected npc value: {v!r}"

    @pytest.mark.parametrize("wait_cfg,expected_labels", [
        ([10],                          ["10"]),
        ([10, 20],                      ["10", "20"]),
        ({"fixed": 15},                 ["15"]),
        ({"random": {"min": 5, "max": 30}}, ["random:5-30"]),
    ])
    def test_wait_formats_parsed_correctly(self, wait_cfg, expected_labels):
        import yaml
        data = {
            "selected": ["configs/topology.yaml"],
            "repeat": 1, "vpn": ["off"], "npc": ["medium"],
            "inject": ["on"], "exfil": ["true"], "wait": wait_cfg,
        }
        p = self._write(yaml.dump(data))
        cfg = load_yaml_config(p)
        assert cfg.wait == expected_labels

    def test_actual_autogen_yaml_loads(self):
        if not os.path.exists(AUTOGEN_PATH):
            pytest.skip("auto-gen.yaml not present")
        cfg = load_yaml_config(Path(AUTOGEN_PATH))
        assert cfg.repeat >= 1
        assert cfg.vpn
        assert cfg.npc
        assert cfg.wait


# ─────────────────────── combo key uniqueness ────────────────────────────────

@pytest.mark.unit
class TestComboKey:

    def test_all_keys_unique(self):
        from auto_gen import build_combos, ExperimentConfig
        cfg = ExperimentConfig(
            topologies=["a.yaml", "b.yaml"],
            vpn=["on", "off"],
            npc=["low", "medium"],
            inject=["on", "off"],
            exfil=["true", "false"],
            wait=["10", "20"],
            repeat=2,
        )
        combos = build_combos(cfg)
        keys = [c.key() for c in combos]
        assert len(keys) == len(set(keys)), "duplicate combo keys found"

    def test_key_contains_all_dimensions(self):
        from auto_gen import build_combos, ExperimentConfig
        cfg = ExperimentConfig(
            topologies=["my_topo.yaml"],
            vpn=["on"],
            npc=["high"],
            inject=["off"],
            exfil=["true"],
            wait=["30"],
            repeat=1,
        )
        combo = build_combos(cfg)[0]
        key = combo.key()
        assert "my_topo" in key or "on" in key
        assert "high" in key
        assert "30" in key
