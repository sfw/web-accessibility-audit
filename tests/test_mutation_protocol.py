from __future__ import annotations

import asyncio
import hashlib
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

import pytest

from tools import a11y_flow_check, a11y_scan, a11y_url_inventory

from loom.tools.registry import ToolContext, ToolResult


@lru_cache(maxsize=1)
def _loom_policy_modules():
    runner_policy_mod = pytest.importorskip(
        "loom.engine.runner.policy",
        reason="Requires Loom runtime dependencies.",
    )
    orchestrator_evidence_mod = pytest.importorskip(
        "loom.engine.orchestrator.evidence",
        reason="Requires Loom runtime dependencies.",
    )
    tool_call_record_cls = pytest.importorskip(
        "loom.engine.runner.types",
        reason="Requires Loom runtime dependencies.",
    ).ToolCallRecord
    task_cls = pytest.importorskip(
        "loom.state.task_state",
        reason="Requires Loom runtime dependencies.",
    ).Task
    return runner_policy_mod, orchestrator_evidence_mod, tool_call_record_cls, task_cls


def _runner_policy():
    return _loom_policy_modules()[0]


def _orchestrator_evidence():
    return _loom_policy_modules()[1]


def _tool_call_record():
    return _loom_policy_modules()[2]


def _task_cls():
    return _loom_policy_modules()[3]


def _run(coro):
    return asyncio.run(coro)


def _is_mutating_file_tool(
    tool_name: str,
    tool_args: dict,
    *,
    is_mutating_tool: bool = False,
) -> bool:
    return _runner_policy().is_mutating_file_tool(
        tool_name=tool_name,
        tool_args=tool_args,
        is_mutating_tool=is_mutating_tool,
        write_mutating_tools=frozenset(),
        spreadsheet_write_operations=frozenset({"create"}),
    )


def _target_paths_for_policy(**kwargs) -> list[str]:
    return _runner_policy().target_paths_for_policy(
        is_mutating_file_tool_fn=_is_mutating_file_tool,
        **kwargs,
    )


def _mutation_paths_for_reseal(**kwargs) -> list[str]:
    paths = _target_paths_for_policy(
        tool_name=kwargs["tool_name"],
        tool_args=kwargs["tool_args"],
        workspace=kwargs["workspace"],
        is_mutating_tool=kwargs["is_mutating_tool"],
        mutation_target_arg_keys=kwargs["mutation_target_arg_keys"],
    )
    seen = set(paths)
    for raw in kwargs["tool_result"].files_changed:
        normalized = _runner_policy().normalize_path_for_policy(
            str(raw),
            kwargs["workspace"],
        )
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        paths.append(normalized)
    return paths


def _patch_scan_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_fetch(url: str, *, cfg, last_request_by_host, warnings):  # noqa: ARG001
        return a11y_scan._FetchResult(
            requested_url=url,
            final_url=url,
            status_code=200,
            content_type="text/html; charset=utf-8",
            body="<html lang='en'><title>ok</title><main>main</main></html>",
            truncated=False,
        )

    monkeypatch.setattr(a11y_scan, "_fetch_url", _fake_fetch)


def _patch_flow_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_fetch(url: str, *, cfg, last_request_by_host, warnings):  # noqa: ARG001
        return a11y_flow_check._FetchResult(
            requested_url=url,
            final_url=url,
            status_code=200,
            content_type="text/html; charset=utf-8",
            body="<html lang='en'><title>Flow</title><main>Complete</main></html>",
            truncated=False,
        )

    monkeypatch.setattr(a11y_flow_check, "_fetch_url", _fake_fetch)


def _patch_inventory_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(a11y_url_inventory, "_discover_from_sitemaps", lambda *a, **k: {})
    monkeypatch.setattr(a11y_url_inventory, "_crawl_same_origin", lambda *a, **k: {})


WriterCase = tuple[
    object,
    tuple[str, ...],
    dict,
    list[str],
    Callable[[pytest.MonkeyPatch], None],
]


@pytest.mark.parametrize(
    ("tool_obj", "target_keys", "args", "expected_files", "patch_fn"),
    [
        (
            a11y_scan.A11yScanTool(),
            ("output_findings_csv",),
            {
                "urls": ["https://example.com/"],
                "output_findings_csv": "reports/findings.csv",
            },
            ["reports/findings.csv"],
            _patch_scan_fetch,
        ),
        (
            a11y_flow_check.A11yFlowCheckTool(),
            ("output_flow_csv", "output_flow_json"),
            {
                "flows": [
                    {
                        "name": "Checkout",
                        "steps": ["https://example.com/checkout"],
                    },
                ],
                "output_flow_csv": "reports/flow.csv",
                "output_flow_json": "reports/flow.json",
            },
            ["reports/flow.csv", "reports/flow.json"],
            _patch_flow_fetch,
        ),
        (
            a11y_url_inventory.A11yUrlInventoryTool(),
            ("output_inventory_csv", "output_sample_csv", "output_templates_csv"),
            {
                "targets": ["https://example.com"],
                "output_inventory_csv": "reports/inventory.csv",
                "output_sample_csv": "reports/sample.csv",
                "output_templates_csv": "reports/templates.csv",
            },
            [
                "reports/inventory.csv",
                "reports/sample.csv",
                "reports/templates.csv",
            ],
            _patch_inventory_discovery,
        ),
    ],
)
def test_workspace_writers_are_mutating_and_emit_relative_files_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_obj: object,
    target_keys: tuple[str, ...],
    args: dict,
    expected_files: list[str],
    patch_fn: Callable[[pytest.MonkeyPatch], None],
) -> None:
    patch_fn(monkeypatch)

    assert bool(getattr(tool_obj, "is_mutating", False)) is True
    assert tuple(getattr(tool_obj, "mutation_target_arg_keys", ())) == target_keys

    result = _run(tool_obj.execute(args, ToolContext(workspace=tmp_path)))
    assert result.success is True
    assert sorted(result.files_changed) == sorted(expected_files)
    assert all(not Path(item).is_absolute() for item in result.files_changed)
    for relpath in expected_files:
        assert (tmp_path / relpath).exists()


def test_output_path_writer_preflight_blocked_without_evidence() -> None:
    runner_policy = _runner_policy()
    tool = a11y_flow_check.A11yFlowCheckTool()
    path = "reports/flow.json"
    task = SimpleNamespace(
        metadata={
            "artifact_seals": {
                path: {
                    "path": path,
                    "sha256": "abc123",
                    "verified_origin": True,
                    "sealed_at": "2026-03-01T12:00:00",
                },
            },
        },
    )
    blocked = runner_policy.validate_sealed_artifact_mutation_policy(
        task=task,
        tool_name=tool.name,
        tool_args={"output_flow_json": path},
        workspace=None,
        is_mutating_tool=tool.is_mutating,
        mutation_target_arg_keys=tool.mutation_target_arg_keys,
        prior_successful_tool_calls=[],
        current_tool_calls=[],
        target_paths_for_policy=_target_paths_for_policy,
        artifact_seal_registry=lambda task_obj: task_obj.metadata["artifact_seals"],
        seal_origin_is_verified=lambda **kwargs: True,
        latest_seal_timestamp=lambda protected_paths: "2026-03-01T12:00:00",
        has_post_seal_confirmation_evidence=lambda **kwargs: False,
    )

    assert blocked is not None
    assert "Sealed artifact mutation blocked" in blocked


def test_output_path_writer_preflight_allows_with_evidence() -> None:
    runner_policy = _runner_policy()
    tool = a11y_flow_check.A11yFlowCheckTool()
    path = "reports/flow.json"
    task = SimpleNamespace(
        metadata={
            "artifact_seals": {
                path: {
                    "path": path,
                    "sha256": "abc123",
                    "verified_origin": True,
                    "sealed_at": "2026-03-01T12:00:00",
                },
            },
        },
    )
    allowed = runner_policy.validate_sealed_artifact_mutation_policy(
        task=task,
        tool_name=tool.name,
        tool_args={"output_flow_json": path},
        workspace=None,
        is_mutating_tool=tool.is_mutating,
        mutation_target_arg_keys=tool.mutation_target_arg_keys,
        prior_successful_tool_calls=[],
        current_tool_calls=[],
        target_paths_for_policy=_target_paths_for_policy,
        artifact_seal_registry=lambda task_obj: task_obj.metadata["artifact_seals"],
        seal_origin_is_verified=lambda **kwargs: True,
        latest_seal_timestamp=lambda protected_paths: "2026-03-01T12:00:00",
        has_post_seal_confirmation_evidence=lambda **kwargs: True,
    )

    assert allowed is None


def test_custom_tool_reseal_is_tool_agnostic_for_tracked_sealed_paths(tmp_path: Path) -> None:
    runner_policy = _runner_policy()
    relpath = "reports/flow.json"
    artifact = tmp_path / relpath
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text('{"state":"old"}\n', encoding="utf-8")
    old_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    task = SimpleNamespace(
        metadata={
            "run_id": "run-1",
            "artifact_seals": {
                relpath: {
                    "path": relpath,
                    "sha256": old_sha,
                    "verified_origin": True,
                },
            },
        },
    )

    artifact.write_text('{"state":"new"}\n', encoding="utf-8")
    updated = runner_policy.reseal_tracked_artifacts_after_mutation(
        task=task,
        workspace=tmp_path,
        tool_name="a11y_flow_check",
        tool_args={"output_flow_json": relpath},
        tool_result=ToolResult.ok("ok", files_changed=[relpath]),
        is_mutating_tool=True,
        mutation_target_arg_keys=("output_flow_json",),
        subtask_id="subtask-1",
        tool_call_id="call-1",
        artifact_seal_registry=lambda task_obj: task_obj.metadata["artifact_seals"],
        mutation_paths_for_reseal=_mutation_paths_for_reseal,
        normalize_path_for_policy=runner_policy.normalize_path_for_policy,
        seal_origin_is_verified=lambda **kwargs: True,
    )

    assert updated == 1
    seal = task.metadata["artifact_seals"][relpath]
    assert seal["tool"] == "a11y_flow_check"
    assert seal["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert seal["previous_sha256"] == old_sha


def test_spreadsheet_create_reseal_avoids_stale_seal_mismatch_at_synthesis(
    tmp_path: Path,
) -> None:
    orchestrator_evidence = _orchestrator_evidence()
    ToolCallRecord = _tool_call_record()
    Task = _task_cls()
    relpath = "reports/findings.csv"
    artifact = tmp_path / relpath
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("id,severity\n1,error\n", encoding="utf-8")
    task = Task(id="task-1", goal="seal", workspace=str(tmp_path), metadata={})

    class _Stub:
        _state = SimpleNamespace(load_evidence_records=lambda task_id: [])

        def _artifact_seal_registry(self, task_obj):
            return orchestrator_evidence._artifact_seal_registry(self, task_obj)

        def _is_intermediate_artifact_path(self, *, task, relpath):  # noqa: ARG002
            return False

        def _task_run_id(self, task):  # noqa: ARG002
            return "run-1"

        def _artifact_content_for_call(self, tool_name, args, result_data):
            return orchestrator_evidence._artifact_content_for_call(
                tool_name,
                args,
                result_data,
            )

        def _backfill_artifact_seals_from_evidence(self, task_obj):
            return orchestrator_evidence._backfill_artifact_seals_from_evidence(self, task_obj)

    stub = _Stub()
    seeded = orchestrator_evidence._record_artifact_seals(
        stub,
        task=task,
        subtask_id="seed-subtask",
        tool_calls=[
            ToolCallRecord(
                tool="write_file",
                args={"path": relpath},
                result=ToolResult.ok("ok", files_changed=[relpath]),
                call_id="call-seed",
            ),
        ],
    )
    assert seeded == 1

    artifact.write_text("id,severity\n1,warning\n", encoding="utf-8")
    passed, mismatches, _validated = orchestrator_evidence._validate_artifact_seals(
        stub,
        task=task,
    )
    assert passed is False
    assert mismatches

    resealed = orchestrator_evidence._record_artifact_seals(
        stub,
        task=task,
        subtask_id="spreadsheet-subtask",
        tool_calls=[
            ToolCallRecord(
                tool="spreadsheet",
                args={"operation": "create", "path": relpath},
                result=ToolResult.ok("ok", files_changed=[relpath]),
                call_id="call-spreadsheet",
            ),
        ],
    )
    assert resealed == 1

    passed, mismatches, validated = orchestrator_evidence._validate_artifact_seals(
        stub,
        task=task,
    )
    assert passed is True
    assert mismatches == []
    assert validated == 1


def test_edit_file_sealed_preflight_behavior_unchanged() -> None:
    runner_policy = _runner_policy()
    path = "analysis.md"
    task = SimpleNamespace(
        metadata={
            "artifact_seals": {
                path: {
                    "path": path,
                    "sha256": "abc123",
                    "verified_origin": True,
                    "sealed_at": "2026-03-01T12:00:00",
                },
            },
        },
    )
    blocked = runner_policy.validate_sealed_artifact_mutation_policy(
        task=task,
        tool_name="edit_file",
        tool_args={"path": path},
        workspace=None,
        is_mutating_tool=True,
        mutation_target_arg_keys=None,
        prior_successful_tool_calls=[],
        current_tool_calls=[],
        target_paths_for_policy=_target_paths_for_policy,
        artifact_seal_registry=lambda task_obj: task_obj.metadata["artifact_seals"],
        seal_origin_is_verified=lambda **kwargs: True,
        latest_seal_timestamp=lambda protected_paths: "2026-03-01T12:00:00",
        has_post_seal_confirmation_evidence=lambda **kwargs: False,
    )
    assert blocked is not None

    allowed = runner_policy.validate_sealed_artifact_mutation_policy(
        task=task,
        tool_name="edit_file",
        tool_args={"path": path},
        workspace=None,
        is_mutating_tool=True,
        mutation_target_arg_keys=None,
        prior_successful_tool_calls=[],
        current_tool_calls=[],
        target_paths_for_policy=_target_paths_for_policy,
        artifact_seal_registry=lambda task_obj: task_obj.metadata["artifact_seals"],
        seal_origin_is_verified=lambda **kwargs: True,
        latest_seal_timestamp=lambda protected_paths: "2026-03-01T12:00:00",
        has_post_seal_confirmation_evidence=lambda **kwargs: True,
    )
    assert allowed is None
