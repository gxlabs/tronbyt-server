#!/bin/bash

pipx install pdm
pdm sync -d

# Get the OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture names to the format used in the releases
case "$ARCH" in
    x86_64)
        ARCH="amd64"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Map OS names
case "$OS" in
    darwin)
        OS="darwin"
        ;;
    linux)
        OS="linux"
        ;;
    mingw*|msys*|cygwin*)
        OS="windows"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Construct the URL
# e.g. https://github.com/tronbyt/pixlet/releases/download/v0.42.1/pixlet_v0.42.1_darwin_amd64.tar.gz
PIXLET_VERSION="v0.42.1"
PIXLET_FILENAME="pixlet_${PIXLET_VERSION}_${OS}_${ARCH}.tar.gz"
PIXLET_URL="https://github.com/tronbyt/pixlet/releases/download/${PIXLET_VERSION}/${PIXLET_FILENAME}"
echo "Downloading Pixlet from ${PIXLET_URL}"

curl -LO "${PIXLET_URL}"
sudo tar -C /usr/local/bin -xvf "${PIXLET_FILENAME}"
sudo mv /usr/local/bin/libpixlet.so /usr/lib/libpixlet.so
rm "${PIXLET_FILENAME}"

echo "Devcontainer setup complete. To start server, invoke with ./run"
