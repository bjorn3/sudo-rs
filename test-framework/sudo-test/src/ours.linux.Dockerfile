FROM debian:trixie-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends apparmor procps sshpass rsyslog socat
WORKDIR /usr/src/sudo
COPY target/build build
# set setuid on install
RUN install -m 4755 build/sudo /usr/bin/sudo && \
    install -m 4755 build/su /usr/bin/su && \
    install -m 755 build/visudo /usr/sbin/visudo && \
    ln -s /usr/bin/sudo /usr/bin/sudoedit
# `apt-get install sudo` creates this directory; creating it in the image saves us the work of creating it in each compliance test
RUN mkdir -p /etc/sudoers.d
# Ensure we use the same shell across OSes
RUN chsh -s /bin/sh
# To ensure we can create a user with uid 1000 and to avoid having to use uid 1001 in test expectations
RUN userdel ubuntu || true
# set the default working directory to somewhere world writable so sudo / su can create .profraw files there
WORKDIR /tmp
# This env var needs to be set when compiled with the dev feature
ENV SUDO_RS_IS_UNSTABLE="I accept that my system may break unexpectedly"
