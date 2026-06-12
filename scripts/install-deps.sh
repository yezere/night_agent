#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-3000}"
INSTALL_JOERN="${INSTALL_JOERN:-1}"
SKIP_OS_DEPS=0
START_SERVER=0

usage() {
  cat <<'EOF'
Usage: scripts/install-deps.sh [options]

Installs night_agent runtime dependencies on a new machine.

Options:
  --serve            Start the web server after installation
  --skip-joern       Do not install Joern
  --skip-os-deps     Do not install OS packages with apt/brew
  -h, --help         Show this help

Environment:
  PORT=3000
  JOERN_HOME=$HOME/joern/joern-cli
  NIGHT_AGENT_RUNS_DIR=<repo>/.night-agent/runs
  INSTALL_JOERN=0
EOF
}

for arg in "$@"; do
  case "$arg" in
    --serve) START_SERVER=1 ;;
    --skip-joern) INSTALL_JOERN=0 ;;
    --skip-os-deps) SKIP_OS_DEPS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[install] unknown option: $arg" >&2; usage; exit 2 ;;
  esac
done

have() {
  command -v "$1" >/dev/null 2>&1
}

sudo_cmd() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo ""
  else
    echo "sudo"
  fi
}

install_os_deps() {
  if [[ "$SKIP_OS_DEPS" -eq 1 ]]; then
    echo "[install] skipping OS packages"
    return
  fi

  if have apt-get; then
    local sudo
    sudo="$(sudo_cmd)"
    echo "[install] installing OS packages with apt"
    $sudo apt-get update
    $sudo apt-get install -y git curl unzip zip openjdk-17-jdk python3 python3-venv ripgrep
    return
  fi

  if have brew; then
    echo "[install] installing OS packages with Homebrew"
    brew install git curl openjdk@17 python ripgrep
    return
  fi

  echo "[install] no supported package manager found; install manually: git curl unzip Java 17 Python 3 ripgrep" >&2
}

install_bun() {
  if have bun; then
    echo "[install] bun: $(bun --version)"
    return
  fi

  if ! have curl; then
    echo "[install] curl is required to install Bun" >&2
    exit 1
  fi

  echo "[install] installing Bun"
  curl -fsSL https://bun.sh/install | bash
  export PATH="$HOME/.bun/bin:$PATH"
  if ! have bun; then
    echo "[install] bun install finished, but bun is not on PATH. Add $HOME/.bun/bin to PATH and rerun." >&2
    exit 1
  fi
}

install_joern() {
  if [[ "$INSTALL_JOERN" != "1" ]]; then
    echo "[install] skipping Joern"
    return
  fi

  local joern_home="${JOERN_HOME:-$HOME/joern/joern-cli}"
  local joern_parent
  joern_parent="$(dirname "$joern_home")"

  if [[ -x "$joern_home/joern" && -x "$joern_home/javasrc2cpg" ]]; then
    echo "[install] joern: $joern_home"
    return
  fi

  if ! have curl; then
    echo "[install] curl is required to install Joern" >&2
    exit 1
  fi

  echo "[install] installing Joern under $joern_parent"
  mkdir -p "$joern_parent"
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  curl -fsSL https://github.com/joernio/joern/releases/latest/download/joern-install.sh -o "$tmp_dir/joern-install.sh"
  chmod +x "$tmp_dir/joern-install.sh"
  (cd "$joern_parent" && "$tmp_dir/joern-install.sh")
  rm -rf "$tmp_dir"

  if [[ ! -x "$joern_home/joern" || ! -x "$joern_home/javasrc2cpg" ]]; then
    echo "[install] Joern installer finished, but $joern_home/joern was not found." >&2
    echo "[install] Set JOERN_HOME to the installed joern-cli directory before starting night_agent." >&2
    return
  fi
  echo "[install] joern installed: $joern_home"
}

install_node_deps() {
  echo "[install] installing Bun workspace dependencies"
  cd "$ROOT_DIR"
  bun install --frozen-lockfile
}

build_web() {
  echo "[install] building web UI"
  cd "$ROOT_DIR/apps/web"
  bun run build
}

prepare_runtime_dirs() {
  local runs_dir="${NIGHT_AGENT_RUNS_DIR:-$ROOT_DIR/.night-agent/runs}"
  mkdir -p "$runs_dir"
  echo "[install] history database dir: $runs_dir"
}

install_os_deps
install_bun
install_joern
install_node_deps
build_web
prepare_runtime_dirs

echo
echo "[install] done"
echo "[install] start with: scripts/start-server.sh"
echo "[install] URL: http://localhost:$PORT/"

if [[ "$START_SERVER" -eq 1 ]]; then
  exec "$ROOT_DIR/scripts/start-server.sh"
fi
