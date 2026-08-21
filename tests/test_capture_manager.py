from types import SimpleNamespace

import pytest

from network import capture_manager
from network.capture_manager import CaptureManager


class FakeInterface:
    def __init__(self, name):
        self.name = name


class FakeNet:
    def __init__(self, node):
        self.node = node

    def __getitem__(self, name):
        return self.node


class FakeProcess:
    def __init__(self):
        self.signaled = []
        self.returncode = None

    def send_signal(self, sig):
        self.signaled.append(sig)

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


class FakeNode:
    def __init__(self):
        self.interfaces = [FakeInterface("eth0"), FakeInterface("lo"), FakeInterface("eth1")]
        self.processes = []

    def intfList(self):
        return self.interfaces

    def popen(self, *args, **kwargs):
        proc = FakeProcess()
        self.processes.append((args, kwargs, proc))
        return proc


@pytest.fixture
def manager(tmp_path):
    cfg = SimpleNamespace(
        devices=["h1"],
        sessiondir=str(tmp_path / "tmp"),
        merged=str(tmp_path / "pcapng"),
        schema_file=str(tmp_path / "schema.json"),
        automatic=True,
        cleanup_enabled=False,
    )
    alloc = SimpleNamespace(node_interfaces={"h1": {"eth0": None}})
    return CaptureManager(
        net=FakeNet(FakeNode()),
        config=SimpleNamespace(nodes=[], databases=[]),
        allocation=alloc,
        capture_cfg=cfg,
    )


def test_start_starts_async_sniffers_for_configured_devices(manager):
    count = manager.start()

    assert count == 2
    assert manager.is_running() is True
    assert len(manager._sniffers) == 2
    keys = list(manager._sniffers.keys())
    assert any("eth0" in k for k in keys)
    assert any("eth1" in k for k in keys)


def test_stop_finalizes_a_capture_session_and_appends_schema_entry(manager, monkeypatch, tmp_path):
    manager.start()

    appended = []

    def fake_pipeline(interface_pcapngs):
        appended.append(interface_pcapngs)

    monkeypatch.setattr(manager, "_run_automatic_pipeline", fake_pipeline)

    result = manager.stop()

    assert result is True
    assert manager.is_running() is False
    assert len(appended) == 1
