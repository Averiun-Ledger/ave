#!/usr/bin/env bash

set -euo pipefail

# docker run --privileged --rm tonistiigi/binfmt --install arm64

export BUILDX_NO_DEFAULT_ATTESTATIONS=1

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"

DOCKER_USERNAME="${DOCKER_USERNAME:-averiun}"
DOCKER_REPO="${DOCKER_REPO:-ave-http}"
NO_CACHE="${NO_CACHE:-false}"

PROD_TAG_ARRAY=("0.8.0-sqlite" "0.8.0-rocksdb")
PROD_DOCKERFILE_ARRAY=(
    "$SCRIPT_DIR/Dockerfile.sqlite"
    "$SCRIPT_DIR/Dockerfile.rocksdb"
)
PROD_FEATURES_ARRAY=(
    "ext-sqlite sqlite prometheus"
    "ext-sqlite rocksdb prometheus"
)

TAG_ARRAY=("${PROD_TAG_ARRAY[@]}")
DOCKERFILE_ARRAY=("${PROD_DOCKERFILE_ARRAY[@]}")
FEATURES_ARRAY=("${PROD_FEATURES_ARRAY[@]}")

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' is not installed." >&2
        exit 1
    fi
}

docker_config_file() {
    local docker_config_root
    docker_config_root="${DOCKER_CONFIG:-$HOME/.docker}"
    printf '%s/config.json' "$docker_config_root"
}

dockerhub_credentials_configured() {
    local config_file
    config_file="$(docker_config_file)"

    if [ ! -f "$config_file" ]; then
        return 1
    fi

    if grep -q '"https://index.docker.io/v1/"' "$config_file"; then
        return 0
    fi

    if grep -q '"credsStore"' "$config_file"; then
        return 0
    fi

    if grep -q '"credHelpers"' "$config_file"; then
        return 0
    fi

    return 1
}

ensure_dockerhub_login() {
    if ! dockerhub_credentials_configured; then
        echo "Error: production mode requires Docker Hub credentials configured." >&2
        echo "Run: docker login" >&2
        exit 1
    fi
}

read_choice() {
    local prompt="$1"
    local value
    read -r -p "$prompt" value
    printf '%s' "$value"
}

build_image() {
    local arch="$1"
    local tag="$2"
    local dockerfile="$3"
    local features="$4"
    local cargo_profile="$5"

    local image_tag="${DOCKER_USERNAME}/${DOCKER_REPO}:${arch}-${tag}"
    local no_cache_args=()

    if [ "$NO_CACHE" = "true" ]; then
        no_cache_args=(--no-cache)
    fi

    echo ""
    echo "Building ${arch^^} with features: $features..."
    echo "Cargo profile: $cargo_profile"

    docker build \
        --build-arg CARGO_PROFILE="$cargo_profile" \
        --build-arg FEATURES="$features" \
        --target "$arch" \
        --tag "$image_tag" \
        "${no_cache_args[@]}" \
        --file "$dockerfile" \
        "$WORKSPACE_ROOT"

    echo "${arch^^} completed."
}

push_image() {
    local arch="$1"
    local tag="$2"
    docker push "${DOCKER_USERNAME}/${DOCKER_REPO}:${arch}-${tag}"
}

annotate_manifest() {
    local arch="$1"
    local tag="$2"
    docker manifest annotate \
        "${DOCKER_USERNAME}/${DOCKER_REPO}:${tag}" \
        "${DOCKER_USERNAME}/${DOCKER_REPO}:${arch}-${tag}" \
        --os linux \
        --arch "$arch"
}

require_command docker

echo "Workspace root: $WORKSPACE_ROOT"
echo "No cache       : $NO_CACHE"
echo ""
echo "Build environment selection:"
echo "1) Production"
echo "2) Development"
ENV_CHOICE="$(read_choice "Select environment (1 or 2): ")"

case "$ENV_CHOICE" in
    1)
        ENVIRONMENT="production"
        ;;
    2)
        ENVIRONMENT="development"
        ;;
    *)
        echo "Error: invalid option. Please select 1 or 2." >&2
        exit 1
        ;;
esac

if [ "$ENVIRONMENT" = "development" ]; then
    CARGO_PROFILE="experimental"

    echo ""
    echo "Architecture selection for development:"
    echo "1) AMD64 only"
    echo "2) ARM64 only"
    echo "3) Both (AMD64 and ARM64)"
    ARCH_CHOICE="$(read_choice "Select architecture (1, 2, or 3): ")"

    case "$ARCH_CHOICE" in
        1)
            BUILD_AMD64=true
            BUILD_ARM64=false
            ;;
        2)
            BUILD_AMD64=false
            BUILD_ARM64=true
            ;;
        3)
            BUILD_AMD64=true
            BUILD_ARM64=true
            ;;
        *)
            echo "Error: invalid option. Please select 1, 2, or 3." >&2
            exit 1
            ;;
    esac

    echo ""
    echo "Database selection for development:"
    echo "1) SQLite only"
    echo "2) RocksDB only"
    echo "3) Both (SQLite and RocksDB)"
    DB_CHOICE="$(read_choice "Select database (1, 2, or 3): ")"

    case "$DB_CHOICE" in
        1)
            BUILD_SQLITE=true
            BUILD_ROCKSDB=false
            ;;
        2)
            BUILD_SQLITE=false
            BUILD_ROCKSDB=true
            ;;
        3)
            BUILD_SQLITE=true
            BUILD_ROCKSDB=true
            ;;
        *)
            echo "Error: invalid option. Please select 1, 2, or 3." >&2
            exit 1
            ;;
    esac

    TAG_ARRAY=()
    DOCKERFILE_ARRAY=()
    FEATURES_ARRAY=()

    if [ "$BUILD_SQLITE" = true ]; then
        TAG_ARRAY+=("${PROD_TAG_ARRAY[0]}-exp")
        DOCKERFILE_ARRAY+=("${PROD_DOCKERFILE_ARRAY[0]}")
        FEATURES_ARRAY+=("${PROD_FEATURES_ARRAY[0]}")
    fi

    if [ "$BUILD_ROCKSDB" = true ]; then
        TAG_ARRAY+=("${PROD_TAG_ARRAY[1]}-exp")
        DOCKERFILE_ARRAY+=("${PROD_DOCKERFILE_ARRAY[1]}")
        FEATURES_ARRAY+=("${PROD_FEATURES_ARRAY[1]}")
    fi

    SKIP_PUSH=true
    SKIP_MANIFEST=true

    echo ""
    echo "Development mode enabled:"
    echo "  - Tag suffix: -exp"
    echo "  - Cargo profile: $CARGO_PROFILE"
    echo "  - Skip Docker Hub push: yes"
    echo "  - Skip manifest creation: yes"
    echo "  - Build AMD64: $BUILD_AMD64"
    echo "  - Build ARM64: $BUILD_ARM64"
    echo "  - Build SQLite: $BUILD_SQLITE"
    echo "  - Build RocksDB: $BUILD_ROCKSDB"
else
    CARGO_PROFILE="release"
    BUILD_AMD64=true
    BUILD_ARM64=true
    BUILD_SQLITE=true
    BUILD_ROCKSDB=true
    SKIP_PUSH=false
    SKIP_MANIFEST=false

    ensure_dockerhub_login

    echo ""
    echo "Production mode enabled:"
    echo "  - Cargo profile: $CARGO_PROFILE"
    echo "  - Full build for both architectures (AMD64 + ARM64)"
    echo "  - Full build for both databases (SQLite + RocksDB)"
    echo "  - Push to Docker Hub: yes"
    echo "  - Create and push manifests: yes"
    echo "  - Docker Hub credentials: configured"
fi

echo ""
CONFIRM="$(read_choice "Continue? (y/n): ")"
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Build cancelled."
    exit 0
fi

for i in "${!FEATURES_ARRAY[@]}"; do
    FEATURES="${FEATURES_ARRAY[i]}"
    TAG="${TAG_ARRAY[i]}"
    DOCKERFILE="${DOCKERFILE_ARRAY[i]}"

    if [ ! -f "$DOCKERFILE" ]; then
        echo "Error: Dockerfile not found: $DOCKERFILE" >&2
        exit 1
    fi

    echo "######################################################################"
    echo "########################## $TAG #########################"
    echo "######################################################################"

    if [ "$BUILD_ARM64" = true ]; then
        build_image "arm64" "$TAG" "$DOCKERFILE" "$FEATURES" "$CARGO_PROFILE"
    fi

    if [ "$BUILD_AMD64" = true ]; then
        build_image "amd64" "$TAG" "$DOCKERFILE" "$FEATURES" "$CARGO_PROFILE"
    fi

    if [ "$SKIP_PUSH" = false ]; then
        echo ""
        echo "Pushing images to Docker Hub..."
        if [ "$BUILD_ARM64" = true ]; then
            push_image "arm64" "$TAG"
        fi
        if [ "$BUILD_AMD64" = true ]; then
            push_image "amd64" "$TAG"
        fi
    else
        echo ""
        echo "Skipping Docker Hub push (development mode)."
    fi

    if [ "$SKIP_MANIFEST" = false ] && [ "$BUILD_AMD64" = true ] && [ "$BUILD_ARM64" = true ]; then
        echo ""
        echo "Creating multi-architecture manifest..."
        docker manifest rm "${DOCKER_USERNAME}/${DOCKER_REPO}:${TAG}" 2>/dev/null || true
        docker manifest create "${DOCKER_USERNAME}/${DOCKER_REPO}:${TAG}" \
            "${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG}" \
            "${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG}"

        annotate_manifest "amd64" "$TAG"
        annotate_manifest "arm64" "$TAG"

        echo ""
        echo "Pushing manifest to Docker Hub..."
        docker manifest push "${DOCKER_USERNAME}/${DOCKER_REPO}:${TAG}"
    elif [ "$SKIP_MANIFEST" = true ]; then
        echo ""
        echo "Skipping manifest creation (development mode)."
    fi

    echo "Process completed for: $TAG"
done

echo ""
echo "######################################################################"

if [ "$ENVIRONMENT" = "production" ]; then
    echo "############################## CLEANING ##############################"
    echo "######################################################################"

    for i in "${!TAG_ARRAY[@]}"; do
        TAG="${TAG_ARRAY[i]}"
        if [ "$BUILD_AMD64" = true ]; then
            echo "Removing local image: ${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG}"
            docker rmi "${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG}" || true
        fi
        if [ "$BUILD_ARM64" = true ]; then
            echo "Removing local image: ${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG}"
            docker rmi "${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG}" || true
        fi
    done
    echo ""
    echo "Local images cleaned up. All images available on Docker Hub."
else
    echo "########################## BUILD SUMMARY #############################"
    echo "######################################################################"
    echo ""
    echo "Images kept locally (development mode)."
    echo "Built images:"
    for i in "${!TAG_ARRAY[@]}"; do
        TAG="${TAG_ARRAY[i]}"
        if [ "$BUILD_AMD64" = true ]; then
            echo "  - ${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG}"
        fi
        if [ "$BUILD_ARM64" = true ]; then
            echo "  - ${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG}"
        fi
    done
fi

echo ""
echo "Build completed!"
