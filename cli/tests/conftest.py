"""Ensure the local `outpost` package is importable when running CLI tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
