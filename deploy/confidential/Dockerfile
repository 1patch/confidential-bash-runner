FROM node:24.13.1-bookworm-slim@sha256:a81a03dd965b4052269a57fac857004022b522a4bf06e7a739e25e18bce45af2 AS node

FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS workspace
RUN apt-get update && apt-get install -y --no-install-recommends bash coreutils python3 git sqlite3 ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /workspace
COPY --from=node /usr/local/bin/node /usr/local/bin/node

FROM node AS bash-runtime
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl bzip2 util-linux \
    && rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in \
      amd64) arch=x86_64; digest=f3ed9131bc252259df150e270154180188f9df56b73a2312940325e1f522a2d6 ;; \
      arm64) arch=aarch64; digest=b7e11d27cbd69370ed7addb6c0d1c33e70e57a153cee57b5fdc5344bf303c7eb ;; \
      *) exit 1 ;; esac \
    && curl -fsSL "https://github.com/google/gvisor/releases/download/release-20260928.0/gvisor-$arch.tar.bz2" -o /tmp/gvisor.tar.bz2 \
    && printf '%s  /tmp/gvisor.tar.bz2\n' "$digest" | sha256sum -c - \
    && mkdir /tmp/gvisor && tar -xjf /tmp/gvisor.tar.bz2 -C /tmp/gvisor \
    && cp /tmp/gvisor/runsc /usr/local/bin/runsc && cp -a /tmp/gvisor/gvisor-bin /usr/local/bin/gvisor-bin && chmod 0755 /usr/local/bin/runsc \
    && rm -rf /tmp/gvisor /tmp/gvisor.tar.bz2
COPY --from=workspace / /opt/sure/rootfs/
WORKDIR /opt/sure
COPY deploy/confidential/package.json ./package.json
COPY deploy/confidential/entrypoint.sh /usr/local/bin/bash-pool-entrypoint
ENTRYPOINT ["/usr/local/bin/bash-pool-entrypoint"]
COPY src/platform/confidential-bash.ts src/platform/agent-capacity.ts src/platform/sandbox-errors.ts ./src/platform/
COPY src/platform/bash-grant.ts src/platform/confidential-bash-server.ts ./src/platform/
COPY scripts/confidential-bash-server.ts scripts/verify-bash-cgroup.ts ./scripts/
CMD ["node", "scripts/confidential-bash-server.ts"]

FROM bash-runtime AS bash-test
COPY tests/confidential-bash-linux.test.ts ./tests/
CMD ["node", "--test", "tests/confidential-bash-linux.test.ts"]
