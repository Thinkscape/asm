ARG BASE=debian:12
FROM ${BASE}
# SUDO: the sudo package (sudo-rs on Ubuntu 26.04).
ARG SUDO=sudo
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus libpam-systemd openssh-server openssh-sftp-server ${SUDO} procps && rm -rf /var/lib/apt/lists/*
# Ubuntu starts sshd through ssh.socket; the test waits for ssh.service.
RUN printf '[Unit]\nDescription=asm test\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n' \
    > /etc/systemd/system/asm-test.service && { systemctl disable ssh.socket 2>/dev/null || true; } \
    && systemctl enable asm-test.service ssh.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
