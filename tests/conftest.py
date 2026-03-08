from __future__ import annotations

import sys
from pathlib import Path


def _prepend_path(path: Path) -> None:
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)


_prepend_path(Path(__file__).resolve().parents[1])
_prepend_path(Path("~/Development/loom/src").expanduser())
