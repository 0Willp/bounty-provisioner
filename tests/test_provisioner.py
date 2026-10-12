#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pure-logic tests for provisioner.py.

Following the workspace convention (recon-workflow / scope-monitoring): these
tests exercise command construction and parsing only. They NEVER invoke the
external binaries (go, git, curl, ...) -- every network/subprocess boundary is
monkeypatched.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

# Import provisioner.py by path (it lives one directory up, outside any package).
_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("provisioner", _ROOT / "provisioner.py")
provisioner = importlib.util.module_from_spec(_SPEC)
sys.modules["provisioner"] = provisioner
_SPEC.loader.exec_module(provisioner)


# --------------------------------------------------------------------------- #
# _go() catalog builder -- the three accepted entry forms
# --------------------------------------------------------------------------- #
def test_go_plain_string_infers_binary_from_module_path():
    (tool,) = provisioner._go(
        "cat", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    assert tool.binary == "subfinder"
    assert tool.module.endswith("subfinder@latest")
    assert tool.category == "cat"
    assert tool.env == ()


def test_go_two_tuple_sets_explicit_binary():
    (tool,) = provisioner._go("cat", ("github.com/owasp-amass/amass/v4/...@master", "amass"))
    assert tool.binary == "amass"
    assert tool.env == ()


def test_go_three_tuple_preserves_env():
    (tool,) = provisioner._go(
        "cat",
        ("github.com/projectdiscovery/katana/cmd/katana@latest", "katana", (("CGO_ENABLED", "1"),)),
    )
    assert tool.binary == "katana"
    assert tool.env == (("CGO_ENABLED", "1"),)


def test_go_strips_trailing_slashes_when_inferring():
    (tool,) = provisioner._go("cat", "github.com/x/y/cmd/foo/@latest")
    assert tool.binary == "foo"


# --------------------------------------------------------------------------- #
# go_version() -- parsing of `go version` output (run() is stubbed out)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "output,expected",
    [
        ("go version go1.22.3 linux/amd64", (1, 22)),
        ("go version go1.21 linux/arm64", (1, 21)),
        ("go version go1.x.y linux/amd64", None),  # non-numeric minor
        ("go version weird output", None),         # no go1* token
    ],
)
def test_go_version_parsing(monkeypatch, output, expected):
    monkeypatch.setattr(provisioner.shutil, "which", lambda _: "/usr/local/go/bin/go")
    monkeypatch.setattr(provisioner, "run", lambda *a, **k: (True, output, ""))
    assert provisioner.go_version() == expected


def test_go_version_none_when_go_absent(monkeypatch):
    monkeypatch.setattr(provisioner.shutil, "which", lambda _: None)
    monkeypatch.setattr(provisioner.Path, "exists", lambda self: False)
    assert provisioner.go_version() is None


# --------------------------------------------------------------------------- #
# sudo_wrap() -- root vs non-root
# --------------------------------------------------------------------------- #
def test_sudo_wrap_as_root(monkeypatch):
    monkeypatch.setattr(provisioner, "IS_ROOT", True)
    assert provisioner.sudo_wrap(["apt-get", "update"]) == ["apt-get", "update"]


def test_sudo_wrap_as_non_root(monkeypatch):
    monkeypatch.setattr(provisioner, "IS_ROOT", False)
    assert provisioner.sudo_wrap(["apt-get", "update"]) == ["sudo", "apt-get", "update"]


# --------------------------------------------------------------------------- #
# have() -- PATH or ~/go/bin
# --------------------------------------------------------------------------- #
def test_have_true_when_on_path(monkeypatch):
    monkeypatch.setattr(provisioner.shutil, "which", lambda _: "/usr/bin/httpx")
    assert provisioner.have("httpx") is True


def test_have_true_when_in_go_bin(monkeypatch, tmp_path):
    (tmp_path / "nuclei").write_text("")
    monkeypatch.setattr(provisioner.shutil, "which", lambda _: None)
    monkeypatch.setattr(provisioner, "GO_BIN", tmp_path)
    assert provisioner.have("nuclei") is True


def test_have_false_when_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(provisioner.shutil, "which", lambda _: None)
    monkeypatch.setattr(provisioner, "GO_BIN", tmp_path)
    assert provisioner.have("does-not-exist") is False


# --------------------------------------------------------------------------- #
# Report / track bookkeeping
# --------------------------------------------------------------------------- #
def test_report_track_routes_to_the_right_bucket():
    report = provisioner.Report()
    report.installed.append("a")
    report.skipped.append("b")
    report.failed.append("c")
    assert (len(report.installed), len(report.skipped), len(report.failed)) == (1, 1, 1)


def test_module_track_appends_to_global_report(monkeypatch):
    fresh = provisioner.Report()
    monkeypatch.setattr(provisioner, "REPORT", fresh)
    provisioner.track("httpx", "installed")
    provisioner.track("katana", "failed")
    assert fresh.installed == ["httpx"]
    assert fresh.failed == ["katana"]


# --------------------------------------------------------------------------- #
# last_line() helper
# --------------------------------------------------------------------------- #
def test_last_line_returns_trimmed_last_line():
    assert provisioner.last_line("first\nsecond\nthird") == "third"


def test_last_line_empty_input():
    assert provisioner.last_line("") == ""
    assert provisioner.last_line(None) == ""


def test_last_line_truncates_to_width():
    assert provisioner.last_line("x" * 200, width=10) == "x" * 10


# --------------------------------------------------------------------------- #
# sha256_file() -- supply-chain verification helper
# --------------------------------------------------------------------------- #
def test_sha256_file_matches_known_digest(tmp_path):
    import hashlib
    payload = b"bounty-provisioner"
    f = tmp_path / "blob"
    f.write_bytes(payload)
    assert provisioner.sha256_file(f) == hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------- #
# go_release_sha256() -- JSON lookup (run() stubbed; no network)
# --------------------------------------------------------------------------- #
def test_go_release_sha256_finds_matching_file(monkeypatch):
    doc = '[{"version":"go1.22.3","files":[' \
          '{"filename":"go1.22.3.linux-amd64.tar.gz","sha256":"deadbeef"}]}]'
    monkeypatch.setattr(provisioner, "run", lambda *a, **k: (True, doc, ""))
    assert provisioner.go_release_sha256("go1.22.3", "go1.22.3.linux-amd64.tar.gz") == "deadbeef"


def test_go_release_sha256_none_on_miss(monkeypatch):
    monkeypatch.setattr(provisioner, "run", lambda *a, **k: (True, "[]", ""))
    assert provisioner.go_release_sha256("go1.22.3", "nope.tar.gz") is None


def test_go_release_sha256_none_on_bad_json(monkeypatch):
    monkeypatch.setattr(provisioner, "run", lambda *a, **k: (True, "not json", ""))
    assert provisioner.go_release_sha256("go1.22.3", "x.tar.gz") is None


# --------------------------------------------------------------------------- #
# Catalog invariants -- guard against copy/paste regressions
# --------------------------------------------------------------------------- #
def test_every_go_tool_has_a_non_empty_unique_binary():
    binaries = [t.binary for t in provisioner.GO_TOOLS]
    assert all(binaries)
    assert len(binaries) == len(set(binaries)), "binarios Go duplicados no catalogo"


def test_no_duplicate_go_modules():
    modules = [t.module for t in provisioner.GO_TOOLS]
    assert len(modules) == len(set(modules)), "modulos Go duplicados no catalogo"


def test_every_go_module_is_versioned():
    # @latest / @master / @vX -- nunca um modulo sem versao fixada.
    assert all("@" in t.module for t in provisioner.GO_TOOLS)


def test_python_tools_have_package_and_binary():
    assert provisioner.PYTHON_TOOLS
    for package, binary in provisioner.PYTHON_TOOLS:
        assert package and binary


def test_stage_flags_match_the_cli_parser():
    parser = provisioner.build_parser()
    dests = {action.dest for action in parser._actions}
    for flag in provisioner.STAGE_FLAGS:
        assert flag in dests, f"etapa {flag} sem flag correspondente no parser"


# --------------------------------------------------------------------------- #
# ensure_path_exports() -- pure filesystem logic (no subprocess)
# --------------------------------------------------------------------------- #
def test_path_exports_fallback_creates_bashrc_and_profile(monkeypatch, tmp_path):
    # Nenhum rc existe -> grava em ~/.bashrc (interativo nao-login) E ~/.profile.
    monkeypatch.setattr(provisioner, "HOME", tmp_path)
    provisioner.ensure_path_exports()
    bashrc = tmp_path / ".bashrc"
    profile = tmp_path / ".profile"
    assert bashrc.exists() and profile.exists()
    assert "# >>> bounty-provisioner >>>" in bashrc.read_text()
    assert "# >>> bounty-provisioner >>>" in profile.read_text()


def test_path_exports_appends_to_existing_rc_without_duplicating(monkeypatch, tmp_path):
    monkeypatch.setattr(provisioner, "HOME", tmp_path)
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("# existente\n")

    provisioner.ensure_path_exports()
    provisioner.ensure_path_exports()  # idempotente: segunda chamada nao duplica

    text = bashrc.read_text()
    assert text.count("# >>> bounty-provisioner >>>") == 1
    # Como um rc ja existia, o fallback nao deve criar ~/.profile.
    assert not (tmp_path / ".profile").exists()
