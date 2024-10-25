FROM rust:1-slim-bookworm AS build
RUN apt-get update && \
    apt-get install -y --no-install-recommends clang libclang-dev libpam0g-dev
# cache the crates.io index in the image for faster local testing
RUN cargo search sudo
WORKDIR /usr/src/sudo
COPY . .
RUN --mount=type=cache,target=/usr/src/sudo/target cargo build --locked --features="dev" --bins && mkdir -p build && cp target/debug/sudo build/sudo && cp target/debug/su build/su && cp target/debug/visudo build/visudo

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends procps sshpass rsyslog
WORKDIR /usr/src/sudo
COPY --from=build /usr/src/sudo/build/* build/
RUN <<EOF
# set setuid on install
install --mode 4755 build/sudo /usr/bin/sudo
install --mode 4755 build/su /usr/bin/su
install --mode 755 build/visudo /usr/sbin/visudo
# `apt-get install sudo` creates this directory; creating it in the image saves us the work of creating it in each compliance test
mkdir -p /etc/sudoers.d
EOF
# set the default working directory to somewhere world writable so sudo / su can create .profraw files there
WORKDIR /tmp
