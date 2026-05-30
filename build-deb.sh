#!/bin/bash
set -e

# Auto-sync version from pyproject.toml
VERSION=$(grep 'version = ' pyproject.toml | head -1 | sed 's/.*version = "\([^"]*\)".*/\1/')
if [ -z "$VERSION" ]; then
    VERSION="0.3.1"
fi

PKG_NAME="filo-forensics_${VERSION}_all"
BUILD_DIR="build/${PKG_NAME}"

echo "Building Filo .deb package v${VERSION}..."

# Clean previous builds
rm -rf build/
mkdir -p "${BUILD_DIR}/opt/filo"
mkdir -p "${BUILD_DIR}/DEBIAN"

# Copy source files to /opt/filo
cp -r filo "${BUILD_DIR}/opt/filo/"
cp -r filo/formats "${BUILD_DIR}/opt/filo/filo/"
cp pyproject.toml "${BUILD_DIR}/opt/filo/"
cp README.md "${BUILD_DIR}/opt/filo/"
cp LICENSE "${BUILD_DIR}/opt/filo/"

# Create models directory
mkdir -p "${BUILD_DIR}/opt/filo/models"
touch "${BUILD_DIR}/opt/filo/models/.gitkeep"

# Copy DEBIAN control files
cp packaging/DEBIAN/control "${BUILD_DIR}/DEBIAN/"

# Auto-sync version in control file
sed -i "s/^Version: .*/Version: ${VERSION}/" "${BUILD_DIR}/DEBIAN/control"

cp packaging/DEBIAN/postinst "${BUILD_DIR}/DEBIAN/"
cp packaging/DEBIAN/prerm "${BUILD_DIR}/DEBIAN/"
cp packaging/DEBIAN/postrm "${BUILD_DIR}/DEBIAN/"

# Set permissions
chmod 755 "${BUILD_DIR}/DEBIAN/postinst"
chmod 755 "${BUILD_DIR}/DEBIAN/prerm"
chmod 755 "${BUILD_DIR}/DEBIAN/postrm"

# Build package
dpkg-deb --build "${BUILD_DIR}"

# Move to root
mv "build/${PKG_NAME}.deb" .

echo ""
echo "✓ Package built successfully: ${PKG_NAME}.deb"
echo ""
echo "Install with:"
echo "  sudo dpkg -i ${PKG_NAME}.deb"
echo ""
echo "Uninstall with:"
echo "  sudo dpkg -r filo-forensics"
