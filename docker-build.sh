#!/usr/bin/env bash
# ============================================================================
# docker-build.sh — excapp-db image build script (a convenience wrapper
# around the Dockerfile)
#
# Default behavior:
#   - Version defaults to 1.0.0 (matching the Dockerfile's APP_VERSION
#     default; override with --version), producing three tags:
#     excapp-db:<version>, excapp-db:<version>-g<git short sha> (when
#     inside a git repo), and excapp-db:latest;
#   - buildx cache mounts reuse dependency build artifacts, so rebuilds
#     only recompile what changed;
#   - Prints a run example after the build completes.
# ============================================================================
set -euo pipefail

# Always run from the repo root so the docker build context is
# unaffected by the caller's location.
cd "$(dirname "$0")"

IMAGE_NAME="excapp-db"
APP_VERSION="1.0.0"
PLATFORM=""
PUSH=0
NO_CACHE=0
TAGS=()
BUILD_ARGS=()

usage() {
    cat <<'EOF'
Usage: ./docker-build.sh [options]

Options:
  -t, --tag <tag>        Full image tag (repeatable), e.g. registry.example.com/excapp-db:0.1.0.
                          Default: excapp-db:<version> [excapp-db:<version>-g<sha>] excapp-db:latest
  -n, --name <name>      Image name (default: excapp-db; ignored when --tag is given)
  -v, --version <ver>    App version used in default tags and APP_VERSION build arg
                          (default: 1.0.0)
  -p, --platform <p>     Target platform, e.g. linux/amd64, linux/arm64.
                          Comma-separated multi-platform requires --push.
      --build-arg <k=v>  Extra docker build arg (repeatable), e.g.
                          --build-arg RUST_IMAGE=rust:1-slim-bookworm
                          --build-arg RUNTIME_IMAGE=debian:bookworm-slim
      --no-cache         Disable build cache
      --push             Push after build (required for multi-platform)
  -h, --help             Show this help

Examples:
  ./docker-build.sh
  ./docker-build.sh -p linux/arm64
  ./docker-build.sh --no-cache
  ./docker-build.sh -t reg.example.com/excapp-db:0.1.0 --push
  ./docker-build.sh -p linux/amd64,linux/arm64 -t reg.example.com/excapp-db:0.1.0 --push
EOF
}

need_value() {
    if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "error: option '$1' requires a value" >&2
        exit 2
    fi
}

# ---------- Argument parsing ----------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t | --tag)
            need_value "$@"
            TAGS+=("$2")
            shift 2
            ;;
        -n | --name)
            need_value "$@"
            IMAGE_NAME="$2"
            shift 2
            ;;
        -v | --version)
            need_value "$@"
            APP_VERSION="$2"
            shift 2
            ;;
        -p | --platform)
            need_value "$@"
            PLATFORM="$2"
            shift 2
            ;;
        --build-arg)
            need_value "$@"
            BUILD_ARGS+=("--build-arg" "$2")
            shift 2
            ;;
        --no-cache)
            NO_CACHE=1
            shift
            ;;
        --push)
            PUSH=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ---------- Pre-flight checks ----------
if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker not found in PATH" >&2
    exit 1
fi

# Multi-platform build results cannot be loaded into local docker; they
# must be pushed directly.
if [[ "$PLATFORM" == *","* && $PUSH -eq 0 ]]; then
    echo "error: multi-platform build (--platform '$PLATFORM') requires --push" >&2
    exit 1
fi

# ---------- Version and default tags ----------
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || true)"

if [[ ${#TAGS[@]} -eq 0 ]]; then
    TAGS+=("${IMAGE_NAME}:${APP_VERSION}")
    if [[ -n "$GIT_SHA" ]]; then
        TAGS+=("${IMAGE_NAME}:${APP_VERSION}-${GIT_SHA}")
    fi
    TAGS+=("${IMAGE_NAME}:latest")
fi

# ---------- Assemble and run the build command ----------
CMD=(docker buildx build)
if [[ -n "$PLATFORM" ]]; then
    CMD+=(--platform "$PLATFORM")
fi
for tag in "${TAGS[@]}"; do
    CMD+=(-t "$tag")
done
CMD+=("${BUILD_ARGS[@]}" --build-arg "APP_VERSION=${APP_VERSION}")
if [[ $NO_CACHE -eq 1 ]]; then
    CMD+=(--no-cache)
fi
if [[ $PUSH -eq 1 ]]; then
    CMD+=(--push)
else
    CMD+=(--load)
fi
CMD+=(.)

echo "+ ${CMD[*]}"
"${CMD[@]}"

# ---------- Build result summary ----------
echo
echo "Build succeeded:"
for tag in "${TAGS[@]}"; do
    echo "  $tag"
done
cat <<'EOF'

Run (streamable mode, mount your config):
  docker run --rm -p 8000:8000 \
    -v "$PWD/config.toml:/etc/excapp-db/config.toml:ro" \
    <image-tag>

Note: set addr = "0.0.0.0" under [app.mcp.streamable] in config.toml,
otherwise the server is only reachable inside the container.
EOF
