ARG base_image="ubuntu:22.04"
ARG image_type="release"
ARG package_location=""

# Set environment variables to avoid user prompts during installation
ARG DEBIAN_FRONTEND=noninteractive

#********************Setup an runtime environment for running.
FROM ${base_image} AS build_image_runtime
ARG DEBIAN_FRONTEND
ARG package_location

# Install runtime environment
RUN apt-get update && \
    apt-get install -y libsodium23 libunbound8 libhidapi-hidraw0 liblmdb0 libssl3 libhidapi-libusb0 libicu70 && \
    apt-get clean

#********************Setup an develop environment for building.
FROM ${base_image} AS build_image_develop
ARG DEBIAN_FRONTEND
ARG package_location

# Install cmake, git and dev environments
RUN apt-get update && \
    apt-get install -y cmake build-essential libsodium-dev libunbound-dev libhidapi-dev liblmdb-dev libssl-dev git && \
    apt-get clean

#********************Package runtime into a Docker image
FROM ${base_image} AS build_image_release
ARG DEBIAN_FRONTEND
ARG APP_DEPENDENCIES
ARG package_location

# Create and set the working directory
WORKDIR /opt/qubic/oc_verifier

# Copy the requirements.txt file
COPY ${package_location}/ /opt/qubic/oc_verifier

# 
ENV LD_LIBRARY_PATH="/opt/qubic/oc_verifier/lib/boost"

# Place holder to trigger above build
FROM build_image_${image_type}
ARG DEBIAN_FRONTEND
ARG APP_DEPENDENCIES
ARG CMD_BUILD
ARG package_location