#!/usr/bin/env bash
# LinkWarden startup script.
#
# - Verifies python3 is present.
# - Creates ./.venv on first run.
# - Installs dependencies from requirements.txt + sanity-checks critical
#   imports and installs any that are missing (handles the fact that
#   requirements.txt is missing python-Levenshtein and has duplicates).
# - Generates datasets if missing.
# - Trains the phishing model if missing (or if LINKWARDEN_RETRAIN=1).
# - Boots the Flask server, which serves the frontend templates + APIs.
#
# Env overrides:
#   LINKWARDEN_HOST     bind host    (default 0.0.0.0)
#   LINKWARDEN_PORT     bind port    (default 5000)
#   LINKWARDEN_RETRAIN  set to 1 to force model retraining
#   LINKWARDEN_NO_VENV  set to 1 to use the system Python instead of ./.venv

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

VENV_DIR="$PROJECT_DIR/.venv"
HOST="${LINKWARDEN_HOST:-0.0.0.0}"
PORT="${LINKWARDEN_PORT:-5000}"
RETRAIN="${LINKWARDEN_RETRAIN:-0}"
NO_VENV="${LINKWARDEN_NO_VENV:-0}"

section() {
  printf '\n================================================\n  %s\n================================================\n' "$1"
}

section "LinkWarden startup"

# ---------------------------------------------------------------------------
# 1. Python check
# ---------------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required but not installed." >&2
  exit 1
fi
echo "[ok]  python3: $(python3 --version 2>&1)"

# ---------------------------------------------------------------------------
# 2. Virtualenv (unless suppressed)
# ---------------------------------------------------------------------------
if [ "$NO_VENV" = "1" ]; then
  PY="$(command -v python3)"
  PIP="$PY -m pip"
  echo "[ok]  using system python at $PY (LINKWARDEN_NO_VENV=1)"
else
  if [ ! -d "$VENV_DIR" ]; then
    echo "[..] creating virtualenv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
  else
    echo "[ok]  virtualenv exists at $VENV_DIR"
  fi
  PY="$VENV_DIR/bin/python"
  PIP="$VENV_DIR/bin/pip"
fi

# ---------------------------------------------------------------------------
# 3. Pip upgrade + best-effort requirements install
# ---------------------------------------------------------------------------
$PY -m pip install --upgrade pip --quiet 2>/dev/null || true

if [ -f requirements.txt ]; then
  echo "[..] installing requirements.txt"
  if ! $PIP install -r requirements.txt --quiet 2>/tmp/linkwarden-pip.log; then
    echo "[!!] requirements.txt install reported errors; will sanity-check imports anyway"
    tail -5 /tmp/linkwarden-pip.log >&2 || true
  fi
fi

# ---------------------------------------------------------------------------
# 4. Sanity-check imports; install any missing packages individually
# ---------------------------------------------------------------------------
# Maps Python module name -> pip package name (when they differ).
pkg_for_module() {
  case "$1" in
    Levenshtein) echo "python-Levenshtein" ;;
    whois)       echo "python-whois" ;;
    dns)         echo "dnspython" ;;
    sklearn)     echo "scikit-learn" ;;
    flask_cors)  echo "flask-cors" ;;
    *)           echo "$1" ;;
  esac
}

REQUIRED_MODULES=(flask flask_cors sklearn pandas numpy tldextract whois dns requests joblib Levenshtein)
MISSING_PKGS=()

for mod in "${REQUIRED_MODULES[@]}"; do
  if ! $PY -c "import $mod" >/dev/null 2>&1; then
    MISSING_PKGS+=("$(pkg_for_module "$mod")")
  fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
  echo "[..] installing missing packages: ${MISSING_PKGS[*]}"
  $PIP install --quiet "${MISSING_PKGS[@]}"
else
  echo "[ok]  all critical imports present"
fi

# ---------------------------------------------------------------------------
# 5. Datasets
# ---------------------------------------------------------------------------
if [ ! -s datasets/phishing_urls.csv ] || [ ! -s datasets/legitimate_dataset.csv ]; then
  echo "[..] generating datasets"
  $PY model/generate_datasets.py
else
  echo "[ok]  datasets present (legit + phishing)"
fi

# ---------------------------------------------------------------------------
# 6. Model artefact
# ---------------------------------------------------------------------------
if [ ! -f model/phishing_model.pkl ] || [ "$RETRAIN" = "1" ]; then
  if [ "$RETRAIN" = "1" ]; then
    echo "[..] LINKWARDEN_RETRAIN=1 — retraining model"
  else
    echo "[..] model artefact missing — training (~20s)"
  fi
  $PY model/train_model.py
else
  echo "[ok]  model artefact present (model/phishing_model.pkl)"
fi

# ---------------------------------------------------------------------------
# 7. Start Flask (frontend templates are served by the same app)
# ---------------------------------------------------------------------------
section "starting Flask server"
echo "  bind:    http://$HOST:$PORT"
echo "  open:    http://127.0.0.1:$PORT"
echo "  routes:  /  /bert  /report  /api/analyze  /api/analyze-message"
echo "           /api/geo  /api/report  /api/reports"
echo "  stop:    Ctrl+C"
echo ""

export LINKWARDEN_HOST="$HOST"
export LINKWARDEN_PORT="$PORT"

# app.py currently hardcodes 0.0.0.0:5000; if the user overrode HOST/PORT,
# launch via flask CLI which honors --host/--port.
if [ "$HOST" != "0.0.0.0" ] || [ "$PORT" != "5000" ]; then
  cd backend
  exec $PY -m flask --app app run --host "$HOST" --port "$PORT"
else
  exec $PY backend/app.py
fi
