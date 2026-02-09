#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")
SUDO_RS_VERSION="$(cargo metadata --format-version 1 --manifest-path "$PROJECT_DIR/Cargo.toml" | jq '.packages[] | select(.name=="sudo-rs") | .version' -r)"
BUILDER_IMAGE_TAG="sudo-rs-release-builder:latest"
TARGET_DIR_BASE="$PROJECT_DIR/target/pkg"

set -eo pipefail

# Clear any previous builds
rm -rf "$TARGET_DIR_BASE"

# Fetch the date from the changelog
DATE=$(grep -m1 '^##' "$PROJECT_DIR"/CHANGELOG.md | grep -o '[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}')

source_dir="$TARGET_DIR_BASE/source"
mkdir -p "$source_dir" "$source_dir/docs"

# Necessary for building executables
cp -r "$PROJECT_DIR/Cargo.toml" "$PROJECT_DIR/Cargo.lock" "$PROJECT_DIR/src" "$source_dir/"
# Necessary for testing
cp -r "$PROJECT_DIR/test-framework/" "$source_dir/" && rm -r "$source_dir/test-framework/target"
# Documentation
cp "$PROJECT_DIR/COPYRIGHT" "$PROJECT_DIR"/LICENSE-* "$PROJECT_DIR/README.md" "$PROJECT_DIR/CHANGELOG.md" "$PROJECT_DIR/SECURITY.md" "$source_dir/"
cp -r "$PROJECT_DIR/docs/man" "$source_dir/docs/"
# Necessary to regenerate bindings and man pages and rebuild a release
cp -r "$PROJECT_DIR/Makefile" "$PROJECT_DIR/util" "$source_dir/"

mkdir -p "$source_dir/.cargo" "$source_dir/test-framework/.cargo"
cd "$source_dir" && cargo vendor > "$source_dir/.cargo/config.toml"
cd "$source_dir/test-framework" && cargo vendor > "$source_dir/test-framework/.cargo/config.toml"

# Build binaries
docker build --pull --tag "$BUILDER_IMAGE_TAG" --file "$SCRIPT_DIR/Dockerfile-release" "$SCRIPT_DIR"
docker run --rm --user "$(id -u):$(id -g)" -v "$source_dir:/build" -w "/build" --network none "$BUILDER_IMAGE_TAG" cargo clean --frozen
docker run --rm --user "$(id -u):$(id -g)" -v "$source_dir:/build" -w "/build" --network none "$BUILDER_IMAGE_TAG" cargo build --frozen --release --features pam-login,apparmor

# Set target directories
target_dir_sudo="$TARGET_DIR_BASE/sudo"
target_dir_su="$TARGET_DIR_BASE/su"
target_sudo="$TARGET_DIR_BASE/sudo-$SUDO_RS_VERSION.tar.gz"
target_su="$TARGET_DIR_BASE/su-$SUDO_RS_VERSION.tar.gz"
target_source="$TARGET_DIR_BASE/source-$SUDO_RS_VERSION.tar.gz"

# Show what is happening
set -x

# Build sudo
umask u=rwx,g=rx,o=rx
mkdir -p "$target_dir_sudo/bin"
mkdir -p "$target_dir_sudo/share/man/man8"
mkdir -p "$target_dir_sudo/share/man/man5"
cp "$source_dir/target/release/sudo" "$target_dir_sudo/bin/sudo"
cp "$source_dir/target/release/visudo" "$target_dir_sudo/bin/visudo"
ln -s sudo "$target_dir_sudo/bin/sudoedit"
cp "$source_dir/docs/man/sudo.8.man" "$target_dir_sudo/share/man/man8/sudo.8"
cp "$source_dir/docs/man/visudo.8.man" "$target_dir_sudo/share/man/man8/visudo.8"
cp "$source_dir/docs/man/sudoers.5.man" "$target_dir_sudo/share/man/man5/sudoers.5"
ln -s "sudo.8" "$target_dir_sudo/share/man/man8/sudoedit.8"
mkdir -p "$target_dir_sudo/share/doc/sudo-rs/sudo"
cp "$source_dir/README.md" "$target_dir_sudo/share/doc/sudo-rs/sudo/README.md"
cp "$source_dir/CHANGELOG.md" "$target_dir_sudo/share/doc/sudo-rs/sudo/CHANGELOG.md"
cp "$source_dir/SECURITY.md" "$target_dir_sudo/share/doc/sudo-rs/sudo/SECURITY.md"
cp "$source_dir/COPYRIGHT" "$target_dir_sudo/share/doc/sudo-rs/sudo/COPYRIGHT"
cp "$source_dir/LICENSE-APACHE" "$target_dir_sudo/share/doc/sudo-rs/sudo/LICENSE-APACHE"
cp "$source_dir/LICENSE-MIT" "$target_dir_sudo/share/doc/sudo-rs/sudo/LICENSE-MIT"

fakeroot -- bash <<EOF
set -eo pipefail
set -x
chown -R root:root "$target_dir_sudo"
chmod +xs "$target_dir_sudo/bin/sudo"
chmod +x "$target_dir_sudo/bin/visudo"
(cd $target_dir_sudo && tar --mtime="UTC $DATE 00:00:00" --sort=name --use-compress-program='gzip -9n' -cpvf "$target_sudo" *)
EOF

# Build su
mkdir -p "$target_dir_su/bin"
mkdir -p "$target_dir_su/share/man/man1"
cp "$source_dir/target/release/su" "$target_dir_su/bin/su"
cp "$source_dir/docs/man/su.1.man" "$target_dir_su/share/man/man1/su.1"
mkdir -p "$target_dir_su/share/doc/sudo-rs/su"
cp "$source_dir/README.md" "$target_dir_su/share/doc/sudo-rs/su/README.md"
cp "$source_dir/CHANGELOG.md" "$target_dir_su/share/doc/sudo-rs/su/CHANGELOG.md"
cp "$source_dir/SECURITY.md" "$target_dir_su/share/doc/sudo-rs/su/SECURITY.md"
cp "$source_dir/COPYRIGHT" "$target_dir_su/share/doc/sudo-rs/su/COPYRIGHT"
cp "$source_dir/LICENSE-APACHE" "$target_dir_su/share/doc/sudo-rs/su/LICENSE-APACHE"
cp "$source_dir/LICENSE-MIT" "$target_dir_su/share/doc/sudo-rs/su/LICENSE-MIT"

fakeroot -- bash <<EOF
set -eo pipefail
set -x
chown -R root:root "$target_dir_su"
chmod +xs "$target_dir_su/bin/su"
(cd $target_dir_su && tar --mtime="UTC $DATE 00:00:00" --sort=name --use-compress-program='gzip -9n' -cpvf "$target_su" *)
EOF

rm -rf "$source_dir/target"
(cd "$source_dir" && tar --mtime="UTC $DATE 00:00:00" --sort=name --use-compress-program='gzip -9n' -cvf "$target_source" *)

(cd $TARGET_DIR_BASE && sha256sum -b *-$SUDO_RS_VERSION.tar.gz > "$TARGET_DIR_BASE/SHA256SUMS")
