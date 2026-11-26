ARG BASE=debian:12
FROM ${BASE}
# SUDO: the sudo package (sudo-rs on Ubuntu 26.04).
ARG SUDO=sudo
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus libpam-systemd openssh-server openssh-sftp-server ${SUDO} procps && rm -rf /var/lib/apt/lists/*
# Ubuntu starts sshd through ssh.socket; the test waits for ssh.service.
RUN printf '[Unit]\nDescription=asm test\n[Service]\nExecStart=/bin/sleep infinity\nExecReload=/bin/true\n[Install]\nWantedBy=multi-user.target\n' \
    > /etc/systemd/system/asm-test.service && { systemctl disable ssh.socket 2>/dev/null || true; } \
    && systemctl enable asm-test.service ssh.service
# Files restricted leases may read: one in a root-only directory, and a symlink there to a
# file asm must not show. /etc/cron.d is where a privileged lease leaves a change.
RUN install -d -m 0700 /etc/asm-test && printf 'asm-test config 42\n' > /etc/asm-test/app.conf \
    && chmod 0644 /etc/asm-test/app.conf && ln -s /etc/shadow /etc/asm-test/shadow && mkdir -p /etc/cron.d
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
