"""Shared pytest fixtures and markers.

Markers:
    unit        — pure Python, no Mininet, no root required
    integration — requires Mininet + root; skipped automatically when absent
    physics     — TC parameter verification (no Mininet, no external files)
"""

import os
import sys
import glob
import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

CONFIGS_DIR = os.path.join(ROOT, "configs")
ALL_TOPOLOGY_PATHS = sorted(glob.glob(os.path.join(CONFIGS_DIR, "topology*.yaml")))


def pytest_configure(config):
    config.addinivalue_line("markers", "unit: pure Python — no Mininet")
    config.addinivalue_line("markers", "integration: requires root + Mininet")
    config.addinivalue_line("markers", "physics: TC parameter verification")


def _mininet_available() -> bool:
    try:
        import mininet.net  # noqa: F401
        return os.geteuid() == 0
    except ImportError:
        return False


def pytest_collection_modifyitems(config, items):
    skip_integration = pytest.mark.skip(reason="Mininet not available or not root")
    for item in items:
        if "integration" in item.keywords and not _mininet_available():
            item.add_marker(skip_integration)


@pytest.fixture(scope="session", params=ALL_TOPOLOGY_PATHS,
                ids=lambda p: os.path.splitext(os.path.basename(p))[0])
def topology_config(request):
    from config_loader import load_config
    return load_config(request.param), request.param


@pytest.fixture(scope="session", params=ALL_TOPOLOGY_PATHS,
                ids=lambda p: os.path.splitext(os.path.basename(p))[0])
def topology_allocation(request):
    from config_loader import load_config
    from network.ip_allocator import allocate
    cfg = load_config(request.param)
    return cfg, allocate(cfg), request.param
