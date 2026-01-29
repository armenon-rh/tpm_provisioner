FROM alpine:latest AS builder
RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    openssl \
    openssl-dev \
    rust \
    cargo \
    tpm2-tss-dev \
    tpm2-tools \
    tpm2-tss-tcti-mssim \
    bash

WORKDIR /app
RUN git clone https://github.com/TrustedComputingGroup/TPM.git && \
    cd /app/TPM/TPMCmd && \
    mkdir -p build && \
    cmake -S . -B ./build/ -G "Unix Makefiles" && \
    cmake --build build/


FROM builder AS runner
WORKDIR /app/tpm_provisioner

COPY . .

RUN chmod +x entrypoint.sh verify.sh && \
    mv entrypoint.sh /usr/local/bin/ && \
    mv verify.sh /usr/local/bin/verify

RUN cargo build

#ENV TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=2321"

ENTRYPOINT ["entrypoint.sh"]
CMD ["/bin/bash"]