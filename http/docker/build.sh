#!/bin/bash

# docker run --privileged --rm tonistiigi/binfmt --install arm64
set -e

# === IMPORTANTE ===
# Evitar que cada imagen se suba como manifest list (OCI index con attestations)
export BUILDX_NO_DEFAULT_ATTESTATIONS=1

DOCKER_USERNAME="averiun"
DOCKER_REPO="ave-http"
PROD_TAG_ARRAY=("0.8.0-sqlite" "0.8.0-rocksdb")
PROD_DOCKERFILE_ARRAY=("./ave/http/docker/Dockerfile.sqlite" "./ave/http/docker/Dockerfile.rocksdb")
PROD_FEATURES_ARRAY=("ext-sqlite sqlite prometheus" "ext-sqlite rocksdb prometheus")

# Arrays that will be used for the current build
TAG_ARRAY=("${PROD_TAG_ARRAY[@]}")
DOCKERFILE_ARRAY=("${PROD_DOCKERFILE_ARRAY[@]}")
FEATURES_ARRAY=("${PROD_FEATURES_ARRAY[@]}")

# Ask for environment
echo "Build environment selection:"
echo "1) Production"
echo "2) Development"
read -p "Select environment (1 or 2): " ENV_CHOICE

case $ENV_CHOICE in
    1)
        ENVIRONMENT="production"
        ;;
    2)
        ENVIRONMENT="development"
        ;;
    *)
        echo "Error: Invalid option. Please select 1 or 2."
        exit 1
        ;;
esac

# Configuration based on environment
if [ "$ENVIRONMENT" = "development" ]; then
    echo ""
    echo "Architecture selection for development:"
    echo "1) AMD64 only"
    echo "2) ARM64 only"
    echo "3) Both (AMD64 and ARM64)"
    read -p "Select architecture (1, 2, or 3): " ARCH_CHOICE

    case $ARCH_CHOICE in
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
            echo "Error: Invalid option. Please select 1, 2, or 3."
            exit 1
            ;;
    esac

    echo ""
    echo "Database selection for development:"
    echo "1) SQLite only"
    echo "2) RocksDB only"
    echo "3) Both (SQLite and RocksDB)"
    read -p "Select database (1, 2, or 3): " DB_CHOICE

    case $DB_CHOICE in
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
            echo "Error: Invalid option. Please select 1, 2, or 3."
            exit 1
            ;;
    esac

    # Build arrays based on database selection
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
    echo "  - Skip Docker Hub push: yes"
    echo "  - Skip manifest creation: yes"
    echo "  - Build AMD64: $BUILD_AMD64"
    echo "  - Build ARM64: $BUILD_ARM64"
    echo "  - Build SQLite: $BUILD_SQLITE"
    echo "  - Build RocksDB: $BUILD_ROCKSDB"
else
    BUILD_AMD64=true
    BUILD_ARM64=true
    BUILD_SQLITE=true
    BUILD_ROCKSDB=true
    SKIP_PUSH=false
    SKIP_MANIFEST=false

    echo ""
    echo "Production mode enabled:"
    echo "  - Full build for both architectures (AMD64 + ARM64)"
    echo "  - Full build for both databases (SQLite + RocksDB)"
    echo "  - Push to Docker Hub: yes"
    echo "  - Create and push manifests: yes"
fi

echo ""
read -p "Continue? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Build cancelled."
    exit 0
fi

for i in "${!FEATURES_ARRAY[@]}"; do
    FEATURES="${FEATURES_ARRAY[i]}"
    TAG="${TAG_ARRAY[i]}"
    DOCKERFILE="${DOCKERFILE_ARRAY[i]}"

    echo "######################################################################"
    echo "########################## $TAG #########################"
    echo "######################################################################"

    # Build ARM64 if enabled
    if [ "$BUILD_ARM64" = true ]; then
        echo ""
        echo "Building ARM64 with features: $FEATURES..."
        docker build --no-cache --build-arg FEATURES="$FEATURES" -t ${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG} --target arm64 -f $DOCKERFILE .
        echo "ARM64 completed."
    fi

    # Build AMD64 if enabled
    if [ "$BUILD_AMD64" = true ]; then
        echo ""
        echo "Building AMD64 with features: $FEATURES..."
        docker build --no-cache --build-arg FEATURES="$FEATURES" -t ${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG} --target amd64 -f $DOCKERFILE .
        echo "AMD64 completed."
    fi

    # Push images if not skipped
    if [ "$SKIP_PUSH" = false ]; then
        echo ""
        echo "Pushing images to Docker Hub..."
        if [ "$BUILD_ARM64" = true ]; then
            docker push ${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG}
        fi
        if [ "$BUILD_AMD64" = true ]; then
            docker push ${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG}
        fi
    else
        echo ""
        echo "Skipping Docker Hub push (development mode)."
    fi

    # Create multi-architecture manifest if not skipped and both architectures were built
    if [ "$SKIP_MANIFEST" = false ] && [ "$BUILD_AMD64" = true ] && [ "$BUILD_ARM64" = true ]; then
        echo ""
        echo "Creating multi-architecture manifest..."
        docker manifest rm ${DOCKER_USERNAME}/${DOCKER_REPO}:${TAG} 2>/dev/null || true
        docker manifest create ${DOCKER_USERNAME}/${DOCKER_REPO}:${TAG} \
            ${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG} \
            ${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG}

        # Annotate architectures
        docker manifest annotate ${DOCKER_USERNAME}/${DOCKER_REPO}:${TAG} ${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG} --os linux --arch amd64
        docker manifest annotate ${DOCKER_USERNAME}/${DOCKER_REPO}:${TAG} ${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG} --os linux --arch arm64

        echo ""
        echo "Pushing manifest to Docker Hub..."
        docker manifest push ${DOCKER_USERNAME}/${DOCKER_REPO}:${TAG}
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
            docker rmi ${DOCKER_USERNAME}/${DOCKER_REPO}:amd64-${TAG} || true
        fi
        if [ "$BUILD_ARM64" = true ]; then
            echo "Removing local image: ${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG}"
            docker rmi ${DOCKER_USERNAME}/${DOCKER_REPO}:arm64-${TAG} || true
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
