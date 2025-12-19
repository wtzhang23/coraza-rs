# This file is adapted from coraza-proxy-wasm/ftw/Dockerfile
# Original work: Copyright 2022 The OWASP Coraza contributors
# Adapted for coraza-rs dynamic module implementation

FROM ghcr.io/coreruleset/go-ftw:1.3.0

RUN apk update && apk add curl

WORKDIR /workspace

ARG CRS_VERSION=v4.14.0

# Download CRS tests only (rules and configs are embedded in coraza via rootfs)
ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz /tmp/coreruleset.tar.gz
RUN cd /tmp && tar -xf coreruleset.tar.gz && \
    mv coreruleset-* /workspace/coreruleset && \
    rm -f coreruleset.tar.gz

COPY ftw.yml /workspace/ftw.yml
COPY tests.sh /workspace/tests.sh

ENTRYPOINT ["sh"]
CMD ["-c", "/workspace/tests.sh"]
