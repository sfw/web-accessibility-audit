from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

Config = pytest.importorskip(
    "loom.config",
    reason="Requires Loom runtime dependencies.",
).Config
ProcessLoader = pytest.importorskip(
    "loom.processes.schema",
    reason="Requires Loom runtime dependencies.",
).ProcessLoader
run_process_tests = pytest.importorskip(
    "loom.processes.testing",
    reason="Requires Loom runtime dependencies.",
).run_process_tests


def test_process_test_function_smoke_case_passes(tmp_path: Path) -> None:
    package_root = Path(__file__).resolve().parents[1]
    loader = ProcessLoader(workspace=package_root)
    process = loader.load(str(package_root))

    results = asyncio.run(
        run_process_tests(
            process,
            config=Config(),
            workspace=tmp_path,
            include_live=False,
            case_id="smoke",
        ),
    )

    assert len(results) == 1
    assert results[0].case_id == "smoke"
    assert results[0].passed is True
