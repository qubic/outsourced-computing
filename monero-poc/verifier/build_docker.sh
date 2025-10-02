#!/bin/bash

# Parse arguments
XMR_ROOT_LOCATION=""
BOOST_ROOT_LOCATION=""
BUILD_ALL=0
VERSION=latest
TESTNET=0

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --xmr-root)
      XMR_ROOT_LOCATION="$2"
      shift 2
      ;;
    --boost-root)
      BOOST_ROOT_LOCATION="$2"
      shift 2
      ;;
    --build-all)
      BUILD_ALL="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --testnet)
      TESTNET_ENABLE="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo
      echo "Options:"
      echo "  --xmr-root PATH        Path to Monero root folder"
      echo "  --boost-root PATH      Path to Boost root folder"
      echo "  --build-all 0|1        Rebuild both runtime and dev image (default: 0)"
      echo "  --version VERSION      Specify build version"
      echo "  --testnet 0|1          Enable dummy test net mode"
      echo "  --help, -h             Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Location to thirdparty
echo "XMR_ROOT_LOCATION=$XMR_ROOT_LOCATION"
echo "BOOST_ROOT_LOCATION=$BOOST_ROOT_LOCATION"

# If this is enabled both runtime and develop image will be re-built
echo "BUILD_ALL=$BUILD_ALL"
echo "VERSION=$VERSION"

echo "TESTNET_ENABLE=$TESTNET_ENABLE"

# Build the environment Docker image
DEV_IMAGE="oc-verifier-dev"
RUNTIME_IMAGE="oc-verifier-rt"
RELEASE_IMAGE="oc-verifier"
DOCKER_SRC_DIR="/opt/qubic/oc_verifier_src"

if [ "$BUILD_ALL" == 1 ]; then
    # Trigger build the runtime image
    echo "Building the runtime Docker image"
    docker build -f Dockerfile --build-arg image_type=runtime -t ${RUNTIME_IMAGE} .

    # Build the dev image with tool for compilation
    echo "Building the develop Docker image"
    docker build -f Dockerfile --build-arg base_image=${RUNTIME_IMAGE} --build-arg image_type=develop -t ${DEV_IMAGE} .
fi


# Compile the code if neccessary
package_location=build_docker
build_cmd="rm -rf ${package_location} || true && \
mkdir ${package_location} && \
cd ${package_location} && \
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=./redist -DTESTNET_ENABLE=${TESTNET_ENABLE} -DXMR_ROOT=/xmr_root -DBOOST_ROOT=/boost_root && \
make install"
install_cmd="echo "
echo $build_cmd
docker run --rm -v ./:${DOCKER_SRC_DIR} -v ${XMR_ROOT_LOCATION}:/xmr_root -v ${BOOST_ROOT_LOCATION}:/boost_root -u $(id -u) ${DEV_IMAGE} bash -c "cd $DOCKER_SRC_DIR && $build_cmd && $install_cmd"

# Package into a new release image base on runtime time
echo "Packaging..."
docker build --build-arg base_image=${RUNTIME_IMAGE} --build-arg image_type=release --build-arg package_location=${package_location}/redist -t ${RELEASE_IMAGE}:${VERSION} .