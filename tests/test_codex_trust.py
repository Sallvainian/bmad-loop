"""Codex trust is checked at the same executable and directory as a session."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import install_bmad_config

from bmad_loop import cli, codex_trust, probe
from bmad_loop.adapters.profile import get_profile
from bmad_loop.install import merge_hooks


def _config(root: Path, commands: dict[str, str] | None = None) -> dict:
    profile = get_profile("codex")
    if commands is None:
        commands = {
            event: f"python3 {root}/.bmad-loop/bmad_loop_hook.py {event}"
            for event in ("SessionStart", "Stop")
        }
    data, _ = merge_hooks({}, commands, profile.hooks.dialect)
    path = root / profile.hooks.config_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return data


def _rpc(root: Path, data: dict, status: str = "trusted") -> dict:
    hooks = [
        {
            "sourcePath": str((root / ".codex/hooks.json").resolve()),
            "eventName": event[0].lower() + event[1:],
            "handlerType": "command",
            "command": data["hooks"][event][0]["hooks"][0]["command"],
            "enabled": True,
            "trustStatus": status,
        }
        for event in ("SessionStart", "Stop")
    ]
    return {"data": [{"cwd": str(root.resolve()), "errors": [], "warnings": [], "hooks": hooks}]}


def test_scripted_app_server_executes_request_sequence_and_reads_environment(tmp_path):
    """An actual zero-token child parses initialize and hooks/list, not a mocked RPC."""
    data = _config(tmp_path)
    reply = _rpc(tmp_path, data)
    script = tmp_path / "codex-stub"
    log = tmp_path / "requests.json"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "requests = []\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line); requests.append(msg)\n"
        "    if msg.get('method') == 'initialize':\n"
        "        print(json.dumps({'id': 1, 'result': {}}), flush=True)\n"
        "    if msg.get('method') == 'hooks/list':\n"
        "        assert os.environ['CODEX_HOME'] == 'test-home'\n"
        f"        open({str(log)!r}, 'w').write(json.dumps(requests))\n"
        f"        print(json.dumps({{'id': 2, 'result': {reply!r}}}), flush=True)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    profile = replace(get_profile("codex"), binary=str(script), env={"CODEX_HOME": "test-home"})
    result = codex_trust.project_hook_trust(tmp_path, profile)
    assert result.status == "trusted", result.reason
    requests = json.loads(log.read_text(encoding="utf-8"))
    assert [item["method"] for item in requests] == ["initialize", "initialized", "hooks/list"]
    assert requests[-1]["params"]["cwds"] == [str(tmp_path.resolve())]


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("start-modified", "untrusted"),
        ("start-omitted", "untrusted"),
        ("modified", "untrusted"),
        ("disabled", "untrusted"),
        ("omitted", "untrusted"),
        ("wrong-command", "untrusted"),
        ("malformed-status", "unverifiable"),
        ("wrong-source", "untrusted"),
    ],
)
def test_trust_refuses_stale_or_unmatched_relay(tmp_path, monkeypatch, mutation, expected):
    data = _config(tmp_path)
    result = _rpc(tmp_path, data)
    hooks = result["data"][0]["hooks"]
    if mutation == "start-modified":
        hooks[0]["trustStatus"] = "modified"
    elif mutation == "start-omitted":
        hooks.pop(0)
    elif mutation == "modified":
        hooks[1]["trustStatus"] = "modified"
    elif mutation == "disabled":
        hooks[1]["enabled"] = False
    elif mutation == "omitted":
        hooks.pop()
    elif mutation == "wrong-command":
        hooks[1]["command"] = "echo unrelated"
    elif mutation == "malformed-status":
        hooks[1]["trustStatus"] = []
    elif mutation == "wrong-source":
        hooks[1]["sourcePath"] = "/tmp/other/hooks.json"
    monkeypatch.setattr(codex_trust, "_hooks_list", lambda *_: result)
    assert codex_trust.project_hook_trust(tmp_path, get_profile("codex")).status == expected


def test_missing_profile_stop_and_unsupported_launch_args_fail_closed(tmp_path, monkeypatch):
    data = _config(tmp_path)
    monkeypatch.setattr(codex_trust, "_hooks_list", lambda *_: _rpc(tmp_path, data))
    profile = get_profile("codex")
    assert (
        codex_trust.project_hook_trust(tmp_path, replace(profile, launch_args=("-c", "x=1"))).status
        == "unverifiable"
    )
    assert (
        codex_trust.project_hook_trust(
            tmp_path, replace(profile, env={"CODEX_HOME": "another"})
        ).status
        == "trusted"
    )
    config_path = tmp_path / profile.hooks.config_path
    config_path.write_text(json.dumps({"hooks": {"SessionStart": data["hooks"]["SessionStart"]}}))
    assert codex_trust.project_hook_trust(tmp_path, profile).status == "untrusted"
    config_path.write_text(json.dumps(data))
    assert (
        codex_trust.project_hook_trust(
            tmp_path,
            replace(profile, hooks=replace(profile.hooks, events={"SessionStart": "SessionStart"})),
        ).status
        == "untrusted"
    )


def test_validate_names_untrusted_hook_and_refuses_worktree_inference(project, monkeypatch, capsys):
    from bmad_loop.install import install_into

    install_bmad_config(project)
    install_into(project.project, clis=("codex",))
    capsys.readouterr()
    policy = project.project / ".bmad-loop/policy.toml"
    policy.write_text('[adapter]\nname = "codex"\n', encoding="utf-8")
    monkeypatch.setattr(
        codex_trust,
        "project_hook_trust",
        lambda *_args, **_kwargs: codex_trust.TrustResult("untrusted", "hook trust stale"),
    )
    cli.main(["validate", "--project", str(project.project), "--json"])
    out, err = capsys.readouterr()
    assert out, err
    doc = json.loads(out)
    findings = [f for f in doc["findings"] if f["check"] == "hooks.trust"]
    assert len(findings) == 1 and findings[0]["severity"] == "problem"
    assert "hook trust stale" in findings[0]["message"]

    policy.write_text(
        '[adapter]\nname = "codex"\n[scm]\nisolation = "worktree"\n', encoding="utf-8"
    )
    cli.main(["validate", "--project", str(project.project), "--json"])
    doc = json.loads(capsys.readouterr().out)
    findings = [f for f in doc["findings"] if f["check"] == "hooks.trust"]
    assert len(findings) == 1 and "worktree" in findings[0]["message"]


def test_validate_does_not_run_project_owned_codex_profile(project, tmp_path, capsys):
    from bmad_loop.install import install_into

    install_bmad_config(project)
    install_into(project.project, clis=("codex",))
    capsys.readouterr()
    policy = project.project / ".bmad-loop/policy.toml"
    policy.write_text('[adapter]\nname = "codex"\n', encoding="utf-8")
    sentinel = tmp_path / "executed"
    binary = project.project / "codex-stub"
    binary.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(sentinel)!r}).write_text('yes')\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    overlay = project.project / ".bmad-loop/profiles/codex.toml"
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text(
        f'name = "codex"\nbinary = "{binary}"\n'
        '[hooks]\ndialect = "codex-hooks-json"\nconfig_path = ".codex/hooks.json"\n'
        'events = { SessionStart = "SessionStart", Stop = "Stop" }\n',
        encoding="utf-8",
    )
    cli.main(["validate", "--project", str(project.project), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert not sentinel.exists()
    finding = next(f for f in doc["findings"] if f["check"] == "hooks.trust")
    assert finding["severity"] == "problem" and "project-owned" in finding["message"]


def test_scan_and_live_probe_refuse_trust_at_their_own_directories(tmp_path, monkeypatch):
    profile = get_profile("codex")
    _config(tmp_path)
    calls = []

    def trust(path, _profile, *, binary=None, marker=None):
        calls.append((path, binary, marker))
        return codex_trust.TrustResult("untrusted", "hook trust stale")

    monkeypatch.setattr(codex_trust, "project_hook_trust", trust)
    monkeypatch.setattr(probe, "run_version_help", lambda binary: probe.FlagFinding(binary, True))
    scanned = probe.scan(
        cli="codex", profile=profile, project=tmp_path, hints=probe.Hints(binary="chosen")
    )
    assert scanned.hook_trust == "untrusted" and calls[-1][:2] == (tmp_path, "chosen")

    class Mux:
        def available(self):
            return True

    class Launcher:
        def __init__(self, **_kwargs):
            pass

        def start(self, *_args):
            pytest.fail("untrusted temporary hook config must stop before launch")

        def kill(self):
            pass

    monkeypatch.setattr(probe, "get_multiplexer", Mux)
    monkeypatch.setattr(probe, "_ProbeLauncher", Launcher)
    monkeypatch.setattr(probe.shutil, "which", lambda _binary: "/bin/true")
    live = probe.probe(
        cli="codex", profile=profile, project=tmp_path, hints=probe.Hints(binary="chosen")
    )
    assert live.hook_trust == "untrusted"
    assert calls[-1][0] != tmp_path and calls[-1][1:] == ("chosen", probe.PROBE_HOOK_NAME)
    assert "temporary probe workspace" in live.warnings[0]


def test_trusted_live_probe_checks_temp_config_then_starts_zero_token_launcher(
    tmp_path, monkeypatch
):
    profile = get_profile("codex")
    events = []

    def trust(path, _profile, *, binary=None, marker=None):
        assert (path / profile.hooks.config_path).is_file()
        events.append(("trust", path, binary, marker))
        return codex_trust.TrustResult("trusted", "hook trust current")

    class Mux:
        def available(self):
            return True

    class Launcher:
        def __init__(self, **_kwargs):
            pass

        def start(self, argv, _env, cwd, _log_file):
            events.append(("start", cwd, argv[0]))
            return "fake-window"

        def kill(self):
            events.append(("kill",))

    class Watcher:
        def __init__(self, _capture_dir):
            pass

        def wait_for(self, *_args, **_kwargs):
            return object()  # scripted Stop; no model turn

    monkeypatch.setattr(codex_trust, "project_hook_trust", trust)
    monkeypatch.setattr(probe, "get_multiplexer", Mux)
    monkeypatch.setattr(probe, "_ProbeLauncher", Launcher)
    monkeypatch.setattr(probe, "SignalWatcher", Watcher)
    monkeypatch.setattr(probe.shutil, "which", lambda _binary: "/bin/true")
    monkeypatch.setattr(probe, "run_version_help", lambda binary: probe.FlagFinding(binary, True))
    monkeypatch.setattr(probe, "discover_transcript", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(probe.time, "sleep", lambda _seconds: None)

    finding = probe.probe(
        cli="codex", profile=profile, project=tmp_path, hints=probe.Hints(binary="chosen")
    )
    assert finding.hook_trust == "trusted"
    assert events[0][0] == "trust" and events[0][1] != tmp_path
    assert events[0][2:] == ("chosen", probe.PROBE_HOOK_NAME)
    assert events[1] == ("start", events[0][1], "chosen")
    assert events[-1] == ("kill",)


def test_probe_json_exits_nonzero_and_names_hook_trust(tmp_path, monkeypatch, capsys):
    _config(tmp_path)
    monkeypatch.setattr(
        codex_trust,
        "project_hook_trust",
        lambda *_args, **_kwargs: codex_trust.TrustResult("untrusted", "hook trust stale"),
    )
    monkeypatch.setattr(probe, "run_version_help", lambda binary: probe.FlagFinding(binary, True))
    monkeypatch.setattr(probe, "discover_transcript", lambda *_args, **_kwargs: None)
    rc = cli.main(
        ["probe-adapter", "codex", "--project", str(tmp_path), "--binary", "chosen", "--json"]
    )
    out, err = capsys.readouterr()
    assert rc == 1 and "FAIL" in err
    doc = json.loads(out)
    assert doc["hook_trust"] == "untrusted"
    assert "hook trust stale" in doc["warnings"][0]


def test_probe_scan_with_unregistered_codex_hooks_is_non_green(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(probe, "run_version_help", lambda binary: probe.FlagFinding(binary, True))
    monkeypatch.setattr(probe, "discover_transcript", lambda *_args, **_kwargs: None)
    rc = cli.main(["probe-adapter", "codex", "--project", str(tmp_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert doc["hooks_registered"] is False
    assert doc["hook_trust"] != "trusted"
    assert any("hook trust" in warning for warning in doc["warnings"])


def test_continuous_unrelated_messages_cannot_extend_rpc_deadline(tmp_path, monkeypatch):
    script = tmp_path / "chatty-codex"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    message = json.loads(line)\n"
        "    if message.get('method') == 'initialize':\n"
        "        print(json.dumps({'id': 1, 'result': {}}), flush=True)\n"
        "    if message.get('method') == 'hooks/list':\n"
        "        while True:\n"
        "            print(json.dumps({'method': 'unrelated'}), flush=True)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    monkeypatch.setattr(codex_trust, "_TIMEOUT_S", 0.1)
    with pytest.raises(TimeoutError):
        codex_trust._hooks_list(str(script), tmp_path, {})
