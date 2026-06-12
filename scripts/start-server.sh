#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-3000}"

export NIGHT_AGENT_RUNS_DIR="${NIGHT_AGENT_RUNS_DIR:-$ROOT_DIR/.night-agent/runs}"
export JOERN_HOME="${JOERN_HOME:-$HOME/joern/joern-cli}"
export NIGHT_AGENT_TRACE_CONCURRENCY="${NIGHT_AGENT_TRACE_CONCURRENCY:-1}"
export NIGHT_AGENT_JOERN_XMX_MB="${NIGHT_AGENT_JOERN_XMX_MB:-2048}"
export NIGHT_AGENT_JOERN_ACTIVE_PROCESSORS="${NIGHT_AGENT_JOERN_ACTIVE_PROCESSORS:-2}"

cd "$ROOT_DIR"
mkdir -p "$NIGHT_AGENT_RUNS_DIR"

echo "[night_agent] runs dir: $NIGHT_AGENT_RUNS_DIR"
echo "[night_agent] joern home: $JOERN_HOME"
echo "[night_agent] joern xmx: ${NIGHT_AGENT_JOERN_XMX_MB}m"
echo "[night_agent] joern active processors: $NIGHT_AGENT_JOERN_ACTIVE_PROCESSORS"
echo "[night_agent] port: $PORT"

exec bun --smol run apps/cli/src/main.ts serve --port "$PORT"
