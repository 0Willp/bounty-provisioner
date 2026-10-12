#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bounty-Provisioner v2.0
Provisiona uma estacao de trabalho de Bug Bounty em Debian/Ubuntu/Kali.

Melhorias sobre a v1.0:
  * preflight de dependencias (go, git, cargo, pipx, sudo) antes de cada etapa;
  * instalacao idempotente -- pula o que ja existe (use --force para reinstalar);
  * instalacao paralela das ferramentas Go (--jobs);
  * binarios Go sao LINKADOS em /usr/local/bin em vez de MOVIDOS para /usr/bin
    (nao quebra o cache do `go install` nem sobrescreve arquivos do dpkg);
  * relatorio final de sucesso/pulado/falha + log completo em ~/bounty/provisioner.log;
  * PATH persistido em ~/.bashrc / ~/.zshrc / ~/.profile;
  * catalogo de ferramentas orientado a dados, agrupado pelo pipeline de recon.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Sequence

VERSION = "2.0"

HOME = Path.home()
BOUNTY_DIR = Path(os.environ.get("BOUNTY_DIR") or HOME / "bounty")
TOOLS_DIR = BOUNTY_DIR / "tools"
TARGETS_DIR = BOUNTY_DIR / "targets"
WORDLISTS_DIR = BOUNTY_DIR / "wordlists"
LOG_FILE = BOUNTY_DIR / "provisioner.log"

GO_BIN = Path(os.environ.get("GOBIN") or (Path(os.environ.get("GOPATH") or HOME / "go") / "bin"))
LOCAL_BIN = Path("/usr/local/bin")

MIN_GO = (1, 21)
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


# --------------------------------------------------------------------------- #
# Catalogo de ferramentas
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class GoTool:
    module: str          # caminho do modulo para `go install`
    binary: str          # nome do binario gerado (usado para pular reinstalacao)
    category: str
    env: tuple = ()      # variaveis extras, ex.: (("CGO_ENABLED", "1"),)


def _go(category, *entries):
    """Aceita 'modulo', ('modulo', 'binario') ou ('modulo', 'binario', env)."""
    out = []
    for entry in entries:
        env = ()
        if isinstance(entry, tuple):
            module, binary = entry[0], entry[1]
            if len(entry) > 2:
                env = entry[2]
        else:
            module = entry
            binary = module.split("@")[0].rstrip("/").split("/")[-1]
        out.append(GoTool(module, binary, category, env))
    return out


GO_TOOLS = (
    # --- Enumeracao de subdominios -------------------------------------------
    _go(
        "Enumeracao de Subdominios",
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
        "github.com/tomnomnom/assetfinder@latest",
        ("github.com/owasp-amass/amass/v4/...@master", "amass"),
        "github.com/hakluke/haktrails@latest",
        "github.com/hueristiq/xsubfind3r/cmd/xsubfind3r@latest",
        "github.com/gwen001/github-subdomains@latest",
        "github.com/gwen001/gitlab-subdomains@latest",
        "github.com/glebarez/cero@latest",
        "github.com/trickest/dsieve@latest",
        "github.com/trickest/mksub@latest",
    )
    # --- Permutacao / Resolucao / DNS ----------------------------------------
    + _go(
        "DNS / Resolucao / Permutacao",
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
        "github.com/projectdiscovery/alterx/cmd/alterx@latest",
        ("github.com/d3mondev/puredns/v2@latest", "puredns"),
        "github.com/hakluke/hakrevdns@latest",
        "github.com/Josue87/gotator@latest",
    )
    # --- Probing HTTP / Portas / Rede ----------------------------------------
    + _go(
        "Probing HTTP / Portas",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "github.com/tomnomnom/httprobe@latest",
        "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
        "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
        "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
        "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
        "github.com/ImAyrix/cut-cdn@latest",
        "github.com/s0md3v/smap/cmd/smap@latest",
        "github.com/hakluke/hakip2host@latest",
        "github.com/hakluke/hakoriginfinder@latest",
        "github.com/hakluke/hakcheckurl@latest",
    )
    # --- Crawling / Coleta de endpoints --------------------------------------
    + _go(
        "Crawling / Endpoints",
        ("github.com/projectdiscovery/katana/cmd/katana@latest", "katana", (("CGO_ENABLED", "1"),)),
        "github.com/jaeles-project/gospider@latest",
        "github.com/hakluke/hakrawler@latest",
        "github.com/edoardottt/cariddi/cmd/cariddi@latest",
        ("github.com/lc/gau/v2/cmd/gau@latest", "gau"),
        "github.com/bp0lr/gauplus@latest",
        "github.com/tomnomnom/waybackurls@latest",
        "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest",
        "github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@latest",
        ("github.com/003random/getJS/v2@latest", "getJS"),
        "github.com/lc/subjs@latest",
        "github.com/dwisiswant0/galer@latest",
        "github.com/detectify/page-fetch@latest",
        "github.com/tomnomnom/meg@latest",
    )
    # --- Fuzzing / Parametros / XSS ------------------------------------------
    + _go(
        "Fuzzing / Parametros / XSS",
        ("github.com/ffuf/ffuf/v2@latest", "ffuf"),
        "github.com/ffuf/pencode@latest",
        ("github.com/OJ/gobuster/v3@latest", "gobuster"),
        "github.com/tomnomnom/gf@latest",
        "github.com/tomnomnom/qsreplace@latest",
        "github.com/tomnomnom/unfurl@latest",
        "github.com/Emoe/kxss@latest",
        "github.com/ferreiraklet/airixss@latest",
        ("github.com/hahwul/dalfox/v2@latest", "dalfox"),
        "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
        "github.com/kleiton0x00/ppmap@latest",
        "github.com/takshal/freq@latest",
    )
    # --- Scanning de vulnerabilidades ----------------------------------------
    + _go(
        "Scanning de Vulnerabilidades",
        ("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "nuclei"),
        "github.com/jaeles-project/jaeles@latest",
        "github.com/rverton/webanalyze/cmd/webanalyze@latest",
        "github.com/projectdiscovery/cvemap/cmd/cvemap@latest",
        "github.com/xm1k3/cent@latest",
        ("github.com/BishopFox/sj@latest", "sj"),
    )
    # --- Takeover / Buckets / Segredos ---------------------------------------
    + _go(
        "Takeover / Buckets / Segredos",
        "github.com/haccer/subjack@latest",
        "github.com/PentestPad/subzy@latest",
        "github.com/pwnesia/dnstake/cmd/dnstake@latest",
        "github.com/musana/mx-takeover@latest",
        "github.com/utkusen/socialhunter@latest",
        "github.com/sa7mon/s3scanner@latest",
        ("github.com/trufflesecurity/trufflehog/v3@latest", "trufflehog"),
        "github.com/Brosck/mantra@latest",
        "github.com/deletescape/goop@latest",
    )
    # --- OSINT / Infra --------------------------------------------------------
    + _go(
        "OSINT / Infraestrutura",
        "github.com/j3ssie/metabigor@latest",
        "github.com/j3ssie/sdlookup@latest",
        "github.com/projectdiscovery/uncover/cmd/uncover@latest",
        "github.com/sensepost/gowitness@latest",
    )
    # --- Utilitarios de pipeline ---------------------------------------------
    + _go(
        "Utilitarios de Pipeline",
        "github.com/tomnomnom/anew@latest",
        "github.com/tomnomnom/gron@latest",
        "github.com/tomnomnom/fff@latest",
        "github.com/tomnomnom/burl@latest",
        "github.com/tomnomnom/comb@latest",
        "github.com/tomnomnom/concurl@latest",
        "github.com/projectdiscovery/notify/cmd/notify@latest",
        "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        "github.com/projectdiscovery/proxify/cmd/proxify@latest",
        "github.com/projectdiscovery/simplehttpserver/cmd/simplehttpserver@latest",
        "github.com/projectdiscovery/pdtm/cmd/pdtm@latest",
    )
)

# (pacote pipx, binario esperado)
PYTHON_TOOLS = [
    ("arjun", "arjun"),
    ("uro", "uro"),
    ("sqlmap", "sqlmap"),
    ("shodan", "shodan"),
    ("censys", "censys"),
    ("bbrf", "bbrf"),
    ("dnsgen", "dnsgen"),
    ("xsstrike", "xsstrike"),
    ("dirsearch", "dirsearch"),
    ("wafw00f", "wafw00f"),
    ("waymore", "waymore"),
    # o pacote `paramspider` no PyPI e um placeholder 0.0.1 -- instala do repo
    ("git+https://github.com/devanshbatham/paramspider.git", "paramspider"),
]

APT_PACKAGES = [
    "python3", "python3-pip", "python3-venv", "pipx", "git", "curl", "wget",
    "jq", "unzip", "zip", "make", "gcc", "build-essential", "libpcap-dev",
    "libssl-dev", "pkg-config", "chromium", "nmap", "whois", "dnsutils", "cargo",
]


# --------------------------------------------------------------------------- #
# Infraestrutura: cores, log, relatorio, execucao
# --------------------------------------------------------------------------- #
class C:
    _tty = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET = "\033[0m" if _tty else ""
    BOLD = "\033[1m" if _tty else ""
    GREEN = "\033[32m" if _tty else ""
    YELLOW = "\033[33m" if _tty else ""
    RED = "\033[31m" if _tty else ""
    CYAN = "\033[36m" if _tty else ""
    DIM = "\033[2m" if _tty else ""


def info(msg):
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def ok(msg):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg):
    print(f"{C.RED}[-]{C.RESET} {msg}")


def mark(success):
    return f"{C.GREEN}[+]{C.RESET}" if success else f"{C.RED}[-]{C.RESET}"


def log(line):
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat(timespec='seconds')} {line}\n")
    except OSError:
        pass  # o log nunca deve derrubar a instalacao


@dataclass
class Report:
    installed: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    failed: list = field(default_factory=list)

    def render(self):
        print(f"\n{C.BOLD}{'=' * 62}{C.RESET}")
        print(f"{C.BOLD} RELATORIO{C.RESET}")
        print(f"{C.BOLD}{'=' * 62}{C.RESET}")
        print(f"  {C.GREEN}instalados{C.RESET}  : {len(self.installed)}")
        print(f"  {C.DIM}ja presentes{C.RESET}: {len(self.skipped)}")
        print(f"  {C.RED}falhas{C.RESET}      : {len(self.failed)}")
        if self.failed:
            print(f"\n{C.RED}Falharam:{C.RESET}")
            for name in sorted(self.failed):
                print(f"    - {name}")
            print(f"\n  Detalhes completos em {LOG_FILE}")


REPORT = Report()


def track(name, action):
    getattr(REPORT, action).append(name)


def sudo_wrap(cmd: Sequence[str]):
    return list(cmd) if IS_ROOT else ["sudo", *cmd]


def run(cmd, cwd=None, stream=False, extra_env=None, timeout=1800):
    """Executa um comando. Lista => sem shell (preferido). String => shell.

    Retorna (sucesso, stdout, stderr). Toda a saida vai para o log.
    """
    shell = isinstance(cmd, str)
    printable = cmd if shell else " ".join(cmd)
    log(f"RUN  {printable}" + (f"  (cwd={cwd})" if cwd else ""))

    env = {**os.environ, **extra_env} if extra_env else None

    try:
        proc = subprocess.run(
            cmd,
            shell=shell,
            cwd=str(cwd) if cwd else None,
            env=env,
            timeout=timeout,
            text=True,
            capture_output=not stream,
        )
    except FileNotFoundError as exc:
        log(f"ERR  {printable}: {exc}")
        return False, "", str(exc)
    except subprocess.TimeoutExpired:
        log(f"ERR  {printable}: timeout apos {timeout}s")
        return False, "", f"timeout apos {timeout}s"

    out = proc.stdout or ""
    error = proc.stderr or ""
    if out.strip():
        log(f"OUT  {out.strip()[:4000]}")
    if error.strip():
        log(f"ERR  {error.strip()[:4000]}")
    return proc.returncode == 0, out, error


def last_line(text, width=90):
    lines = (text or "").strip().splitlines()
    return lines[-1][:width] if lines else ""


def have(binary):
    """Ferramenta disponivel no PATH ou ja compilada em ~/go/bin."""
    return bool(shutil.which(binary)) or (GO_BIN / binary).exists()


def git_sync(repo, dest: Path, update=False):
    if dest.exists():
        if update:
            return run(["git", "-C", str(dest), "pull", "--ff-only"])[0]
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    return run(["git", "clone", "--depth", "1", repo, str(dest)], timeout=3600)[0]


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #
def go_exe():
    return shutil.which("go") or "/usr/local/go/bin/go"


def go_version():
    exe = go_exe()
    if not shutil.which(exe) and not Path(exe).exists():
        return None
    success, out, _ = run([exe, "version"], timeout=60)
    if not success:
        return None
    for token in out.split():
        if token.startswith("go1"):
            parts = token[2:].split(".")
            try:
                return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
            except ValueError:
                return None
    return None


def sha256_file(path: Path):
    """SHA256 em hex de um arquivo, lendo em blocos."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def go_release_sha256(tag, filename):
    """SHA256 oficial de `filename` para a release `tag`, via go.dev/dl/?mode=json.

    Retorna o hex esperado ou None se nao for possivel descobrir.
    """
    success, out, _ = run(["curl", "-fsSL", "https://go.dev/dl/?mode=json&include=all"], timeout=120)
    if not success or not out.strip():
        return None
    try:
        releases = json.loads(out)
    except json.JSONDecodeError:
        return None
    for release in releases:
        if release.get("version") != tag:
            continue
        for item in release.get("files", []):
            if item.get("filename") == filename and item.get("sha256"):
                return item["sha256"]
    return None


def ensure_go():
    """Garante um toolchain Go >= MIN_GO. Instala o tarball oficial se preciso."""
    current = go_version()
    if current and current >= MIN_GO:
        ok(f"Go {current[0]}.{current[1]} detectado.")
        return True

    if current:
        warn(f"Go {current[0]}.{current[1]} e antigo demais (minimo {MIN_GO[0]}.{MIN_GO[1]}). Atualizando...")
    else:
        warn("Go nao encontrado. Instalando o toolchain oficial...")

    arch = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armv6l"}.get(platform.machine(), "amd64")
    success, latest, _ = run(["curl", "-fsSL", "https://go.dev/VERSION?m=text"], timeout=120)
    tag = latest.strip().splitlines()[0] if success and latest.strip() else ""
    if not tag.startswith("go"):
        err("Nao foi possivel descobrir a versao mais recente do Go. Instale manualmente: https://go.dev/dl/")
        return False

    filename = f"{tag}.linux-{arch}.tar.gz"
    url = f"https://go.dev/dl/{filename}"
    tmpdir = Path(tempfile.mkdtemp(prefix="bounty-go-"))
    tarball = tmpdir / filename
    try:
        info(f"Baixando {tag} ({arch})...")
        if not run(["curl", "-fsSL", "-o", str(tarball), url], timeout=1800)[0]:
            err("Falha no download do Go.")
            return False

        expected = go_release_sha256(tag, filename)
        if expected is None:
            err(f"Nao foi possivel obter o SHA256 oficial de {filename}. Abortando por seguranca.")
            return False
        actual = sha256_file(tarball)
        if actual != expected:
            err(f"SHA256 do Go nao confere ({actual[:12]}... != {expected[:12]}...). Abortando.")
            return False
        ok("SHA256 do tarball do Go verificado.")

        run(sudo_wrap(["rm", "-rf", "/usr/local/go"]))
        if not run(sudo_wrap(["tar", "-C", "/usr/local", "-xzf", str(tarball)]), timeout=900)[0]:
            err("Falha ao extrair o Go.")
            return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    os.environ["PATH"] = f"/usr/local/go/bin:{os.environ.get('PATH', '')}"
    ok(f"Go {tag} instalado em /usr/local/go.")
    return True


def preflight(stages):
    """Valida o ambiente antes de comecar. Retorna False se for impossivel seguir."""
    info("Preflight do ambiente...")

    if sys.platform != "linux":
        err(f"Plataforma nao suportada: {sys.platform}. Este provisioner assume Debian/Ubuntu/Kali.")
        return False

    if not IS_ROOT and not shutil.which("sudo"):
        err("Sem privilegios de root e sem `sudo` disponivel.")
        return False

    if not IS_ROOT and not run(["sudo", "-n", "true"], timeout=30)[0]:
        warn("O `sudo` vai pedir senha durante a execucao.")

    missing = [b for b in ("git", "curl", "wget") if not shutil.which(b)]
    if missing and not stages["system"]:
        err(f"Dependencias ausentes: {', '.join(missing)}. Rode com --system primeiro.")
        return False

    if stages["go"] and not ensure_go():
        return False

    if stages["external"] and not shutil.which("cargo"):
        warn("`cargo` ausente -- o fallback de compilacao do Findomain nao estara disponivel.")

    ok("Preflight concluido.")
    return True


# --------------------------------------------------------------------------- #
# Etapas
# --------------------------------------------------------------------------- #
def show_banner():
    print(f"""{C.CYAN}
                0WILLP
    {'-' * 36}
    [+] LIFTING CODE & FINDING BUGS
    [+] STATUS: BEAST MODE
    [+] Bounty-Provisioner v{VERSION}{C.RESET}
""")


def prepare_system():
    info("Atualizando o sistema e instalando dependencias de build...")
    apt_env = {"DEBIAN_FRONTEND": "noninteractive"}
    run(sudo_wrap(["apt-get", "update", "-y"]), extra_env=apt_env, stream=True, timeout=1800)
    run(sudo_wrap(["apt-get", "upgrade", "-y"]), extra_env=apt_env, stream=True, timeout=3600)

    success, _, _ = run(
        sudo_wrap(["apt-get", "install", "-y", *APT_PACKAGES]),
        extra_env=apt_env, stream=True, timeout=3600,
    )
    if success:
        ok("Pacotes de sistema instalados.")
        track("apt packages", "installed")
    else:
        err("Alguns pacotes apt falharam -- veja o log.")
        track("apt packages", "failed")

    if shutil.which("pipx"):
        run(["pipx", "ensurepath", "--force"])


def create_structure():
    info(f"Criando a estrutura de diretorios em {BOUNTY_DIR}...")
    for folder in (BOUNTY_DIR, TOOLS_DIR, TARGETS_DIR, WORDLISTS_DIR):
        folder.mkdir(parents=True, exist_ok=True)
        print(f"    {C.DIM}{folder}{C.RESET}")
    ok("Estrutura pronta.")


def ensure_path_exports():
    """Persiste GOPATH/PATH nos rc dos shells -- sem duplicar se ja existir."""
    marker = "# >>> bounty-provisioner >>>"
    block = "\n".join([
        marker,
        'export GOPATH="$HOME/go"',
        'export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin:$HOME/.local/bin"',
        "# <<< bounty-provisioner <<<",
        "",
    ])
    rc_files = (HOME / ".bashrc", HOME / ".zshrc", HOME / ".profile")
    written = False
    for rc in rc_files:
        if not rc.exists():
            continue
        if marker in rc.read_text(encoding="utf-8", errors="ignore"):
            written = True
            continue
        with rc.open("a", encoding="utf-8") as fh:
            fh.write("\n" + block)
        ok(f"PATH persistido em {rc}")
        written = True

    if not written:
        # Nenhum rc existia -- cria ~/.profile para nao perder o PATH silenciosamente.
        profile = HOME / ".profile"
        with profile.open("a", encoding="utf-8") as fh:
            fh.write("\n" + block)
        ok(f"PATH persistido em {profile} (criado)")


def install_go_tools(force, jobs):
    info(f"Instalando {len(GO_TOOLS)} ferramentas Go (paralelismo: {jobs})...")
    exe = go_exe()

    pending = []
    for tool in GO_TOOLS:
        if not force and have(tool.binary):
            print(f"    {C.DIM}[=] {tool.binary} (ja presente){C.RESET}")
            track(tool.binary, "skipped")
        else:
            pending.append(tool)

    if not pending:
        ok("Todas as ferramentas Go ja estavam instaladas.")
        return

    def install(tool):
        env = {"GO111MODULE": "on"}
        env.update(dict(tool.env))
        success, _, error = run([exe, "install", "-v", tool.module], extra_env=env, timeout=1800)
        return tool, success, error

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for tool, success, error in pool.map(install, pending):
            print(f"    {mark(success)} {tool.binary} {C.DIM}{'' if success else last_line(error)}{C.RESET}")
            track(tool.binary, "installed" if success else "failed")


def link_go_bins():
    """Symlink de ~/go/bin para /usr/local/bin.

    A v1.0 fazia `mv` para /usr/bin: isso esvaziava ~/go/bin (quebrando a
    idempotencia do `go install`) e podia sobrescrever binarios do dpkg.
    """
    if not GO_BIN.is_dir():
        warn(f"{GO_BIN} nao existe -- nada para linkar.")
        return

    info(f"Linkando binarios Go em {LOCAL_BIN}...")
    linked = 0
    for path in sorted(GO_BIN.iterdir()):
        if not path.is_file() or not os.access(path, os.X_OK):
            continue
        target = LOCAL_BIN / path.name
        if target.is_symlink() and target.resolve() == path.resolve():
            continue
        if run(sudo_wrap(["ln", "-sf", str(path), str(target)]), timeout=60)[0]:
            linked += 1
    ok(f"{linked} binario(s) linkado(s) em {LOCAL_BIN}.")


def install_python_tools(force):
    info("Instalando ferramentas Python via pipx...")
    if not shutil.which("pipx"):
        err("pipx ausente. Rode `--system` primeiro (ou `apt install pipx`).")
        track("pipx", "failed")
        return

    for package, binary in PYTHON_TOOLS:
        if not force and shutil.which(binary):
            print(f"    {C.DIM}[=] {binary} (ja presente){C.RESET}")
            track(binary, "skipped")
            continue
        cmd = ["pipx", "install", package]
        if force:
            cmd.append("--force")
        success, _, error = run(cmd, timeout=1200)
        print(f"    {mark(success)} {binary} {C.DIM}{'' if success else last_line(error)}{C.RESET}")
        track(binary, "installed" if success else "failed")


def install_external_tools(update):
    info("Instalando ferramentas externas (git / build / binarios)...")
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    # --- Scripts Python standalone (LinkFinder / SecretFinder) ---------------
    # Dependencias ficam num venv dedicado em vez de poluir o Python do sistema
    # (coerente com o isolamento que o pipx da as outras ferramentas Python).
    venv_dir = TOOLS_DIR / ".venv"
    venv_py = venv_dir / "bin" / "python"
    if not venv_py.exists():
        if not run([sys.executable, "-m", "venv", str(venv_dir)], timeout=300)[0]:
            warn("Falha ao criar o venv de ferramentas -- requirements de LinkFinder/SecretFinder serao pulados.")

    for name, repo in (
        ("LinkFinder", "https://github.com/GerbenJavado/LinkFinder.git"),
        ("SecretFinder", "https://github.com/m4ll0k/SecretFinder.git"),
    ):
        dest = TOOLS_DIR / name
        existed = dest.exists()
        if not git_sync(repo, dest, update=update):
            err(f"{name}: clone falhou.")
            track(name, "failed")
            continue
        req = dest / "requirements.txt"
        if req.exists() and (update or not existed) and venv_py.exists():
            run([str(venv_py), "-m", "pip", "install", "-r", str(req)], timeout=900)
        track(name, "skipped" if (existed and not update) else "installed")
        print(f"    {C.GREEN}[+]{C.RESET} {name} -> {dest}")

    if venv_py.exists():
        print(f"    {C.DIM}Rode LinkFinder/SecretFinder com: {venv_py} <script.py>{C.RESET}")

    # --- Findomain: binario oficial, cargo como fallback ---------------------
    if shutil.which("findomain") and not update:
        print(f"    {C.DIM}[=] findomain (ja presente){C.RESET}")
        track("findomain", "skipped")
    else:
        info("  Findomain: baixando o binario oficial...")
        base = "https://github.com/findomain/findomain/releases/latest/download"
        tmpdir = Path(tempfile.mkdtemp(prefix="bounty-findomain-"))
        zip_path = tmpdir / "findomain-linux.zip"
        bin_path = tmpdir / "findomain"
        try:
            success = run(["curl", "-fsSL", "-o", str(zip_path), f"{base}/findomain-linux.zip"], timeout=900)[0]
            if success:
                success = run(["unzip", "-o", str(zip_path), "-d", str(tmpdir)], timeout=300)[0]
            # Verificacao best-effort: a release publica findomain-linux.zip.sha256.
            if success:
                ok_sum, expected_raw, _ = run(
                    ["curl", "-fsSL", f"{base}/findomain-linux.zip.sha256"], timeout=120)
                expected = expected_raw.split()[0].strip().lower() if ok_sum and expected_raw.strip() else ""
                if expected:
                    if sha256_file(zip_path) != expected:
                        err("  SHA256 do Findomain nao confere -- abortando o binario oficial.")
                        success = False
                    else:
                        ok("  SHA256 do Findomain verificado.")
                else:
                    warn("  Checksum do Findomain indisponivel -- prosseguindo sem verificar.")
            if success:
                run(["chmod", "+x", str(bin_path)], timeout=60)
                success = run(sudo_wrap(["mv", str(bin_path), str(LOCAL_BIN / "findomain")]), timeout=60)[0]
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        if not success and shutil.which("cargo"):
            warn("  Binario indisponivel -- compilando com cargo (demora).")
            success = run(["cargo", "install", "findomain"], timeout=3600)[0]
        print(f"    {mark(success)} findomain")
        track("findomain", "installed" if success else "failed")

    # --- MassDNS -------------------------------------------------------------
    if shutil.which("massdns") and not update:
        print(f"    {C.DIM}[=] massdns (ja presente){C.RESET}")
        track("massdns", "skipped")
    else:
        massdns_dir = TOOLS_DIR / "massdns"
        success = git_sync("https://github.com/blechschmidt/massdns.git", massdns_dir, update=update)
        if success:
            success = run(["make"], cwd=massdns_dir, timeout=1800)[0]
        if success:
            success = run(sudo_wrap(["cp", str(massdns_dir / "bin" / "massdns"), str(LOCAL_BIN)]), timeout=60)[0]
        print(f"    {mark(success)} massdns")
        track("massdns", "installed" if success else "failed")

    # --- Padroes do gf -------------------------------------------------------
    gf_dir = HOME / ".gf"
    gf_dir.mkdir(parents=True, exist_ok=True)
    for name, repo in (
        ("Gf-Patterns", "https://github.com/1ndianl33t/Gf-Patterns.git"),
        ("gf-secrets", "https://github.com/dwisiswant0/gf-secrets.git"),
    ):
        dest = TOOLS_DIR / name
        if git_sync(repo, dest, update=update):
            try:
                for pattern_file in dest.rglob("*.json"):
                    shutil.copy2(pattern_file, gf_dir / pattern_file.name)
                print(f"    {C.GREEN}[+]{C.RESET} {name} -> {gf_dir}")
                track(name, "installed")
            except OSError as exc:
                log(f"ERR  copia dos padroes gf ({name}): {exc}")
                print(f"    {C.RED}[-]{C.RESET} {name}")
                track(name, "failed")
        else:
            print(f"    {C.RED}[-]{C.RESET} {name}")
            track(name, "failed")

    # --- Templates do nuclei -------------------------------------------------
    if have("nuclei"):
        info("  Atualizando templates do nuclei...")
        run([shutil.which("nuclei") or str(GO_BIN / "nuclei"), "-update-templates", "-silent"], timeout=1800)


def download_wordlists(update):
    info("Baixando wordlists (pode demorar)...")
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)

    for name, repo in (
        ("SecLists", "https://github.com/danielmiessler/SecLists.git"),
        ("OneListForAll", "https://github.com/six2dez/OneListForAll.git"),
        ("fuzzdb", "https://github.com/fuzzdb-project/fuzzdb.git"),
    ):
        dest = WORDLISTS_DIR / name
        existed = dest.exists()
        success = git_sync(repo, dest, update=update)
        print(f"    {mark(success)} {name}")
        if success:
            track(name, "skipped" if (existed and not update) else "installed")
        else:
            track(name, "failed")

    assetnote_dir = WORDLISTS_DIR / "data"
    if assetnote_dir.exists() and not update:
        print(f"    {C.DIM}[=] Assetnote (ja presente){C.RESET}")
        track("assetnote", "skipped")
    else:
        success = run(
            ["wget", "-q", "-r", "--no-parent", "-R", "index.html*",
             "https://wordlists-cdn.assetnote.io/data/", "-nH"],
            cwd=WORDLISTS_DIR, timeout=3600,
        )[0]
        print(f"    {mark(success)} Assetnote")
        track("assetnote", "installed" if success else "failed")

    for filename in ("resolvers.txt", "resolvers-trusted.txt"):
        url = f"https://raw.githubusercontent.com/trickest/resolvers/main/{filename}"
        success = run(["wget", "-q", url, "-O", str(WORDLISTS_DIR / filename)], timeout=600)[0]
        print(f"    {mark(success)} {filename}")
        track(filename, "installed" if success else "failed")

    ok(f"Wordlists em {WORDLISTS_DIR}")


def list_tools():
    print(f"\n{C.BOLD}Catalogo do Bounty-Provisioner v{VERSION}{C.RESET}")
    categories = {}
    for tool in GO_TOOLS:
        categories.setdefault(tool.category, []).append(tool.binary)
    for category, binaries in categories.items():
        print(f"\n{C.CYAN}{category}{C.RESET} ({len(binaries)})")
        print("  " + ", ".join(sorted(binaries)))
    print(f"\n{C.CYAN}Python (pipx){C.RESET} ({len(PYTHON_TOOLS)})")
    print("  " + ", ".join(sorted({b for _, b in PYTHON_TOOLS})))
    print(f"\n{C.BOLD}Total Go: {len(GO_TOOLS)}{C.RESET}\n")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
STAGE_FLAGS = ("system", "structure", "go", "python", "external", "wordlists")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="provisioner.py",
        description=f"Bounty-Provisioner v{VERSION} -- provisiona uma workstation de Bug Bounty.",
        epilog="Sem nenhuma flag de etapa, roda o provisionamento completo.",
    )
    parser.add_argument("--system", action="store_true", help="Atualiza o sistema e instala dependencias")
    parser.add_argument("--structure", action="store_true", help="Cria a estrutura de diretorios ~/bounty")
    parser.add_argument("--go", action="store_true", help="Instala as ferramentas Go")
    parser.add_argument("--python", action="store_true", help="Instala as ferramentas Python (pipx)")
    parser.add_argument("--external", action="store_true", help="Instala ferramentas externas (git/build/binarios)")
    parser.add_argument("--wordlists", action="store_true", help="Baixa as wordlists")
    parser.add_argument("--all", action="store_true", help="Roda todas as etapas (padrao)")
    parser.add_argument("--force", action="store_true", help="Reinstala/atualiza mesmo o que ja existe")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4),
                        help="Instalacoes Go em paralelo (padrao: %(default)s)")
    parser.add_argument("--list", action="store_true", help="Lista o catalogo de ferramentas e sai")
    parser.add_argument("--no-banner", action="store_true", help="Nao exibe o banner")
    return parser


def main():
    args = build_parser().parse_args()

    if args.list:
        list_tools()
        return 0

    stages = {flag: getattr(args, flag) for flag in STAGE_FLAGS}
    if args.all or not any(stages.values()):
        stages = {flag: True for flag in STAGE_FLAGS}

    if not args.no_banner:
        show_banner()

    log(f"=== provisioner v{VERSION} | etapas: {[k for k, v in stages.items() if v]} ===")

    if not preflight(stages):
        return 1

    if stages["system"]:
        prepare_system()
    if stages["structure"]:
        create_structure()
        ensure_path_exports()
    if stages["go"]:
        install_go_tools(force=args.force, jobs=max(1, args.jobs))
        link_go_bins()
    if stages["python"]:
        install_python_tools(force=args.force)
    if stages["external"]:
        install_external_tools(update=args.force)
    if stages["wordlists"]:
        download_wordlists(update=args.force)

    REPORT.render()
    print(f"\n{C.GREEN}[!] Provisionamento concluido.{C.RESET}")
    print("    Abra um novo shell (ou `source ~/.bashrc`) para carregar o PATH atualizado.")
    print(f"    Log: {LOG_FILE}")

    return 1 if REPORT.failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrompido pelo usuario.{C.RESET}")
        sys.exit(130)
