"""network — ISP emulator network layer.

Ensures the project root is in sys.path so shared modules (config_loader,
debug, database, services) are importable from within this package regardless
of how the package is invoked.
"""
import sys
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
