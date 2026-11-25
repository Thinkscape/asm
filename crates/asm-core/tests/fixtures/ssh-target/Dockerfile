ARG BASE=debian:12
FROM ${BASE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus libpam-systemd openssh-server openssh-sftp-server sudo procps && rm -rf /var/lib/apt/lists/*
RUN printf '[Unit]\nDescription=asm test\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n' \
    > /etc/systemd/system/asm-test.service && systemctl enable asm-test.service ssh.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
