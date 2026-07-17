# Building the TCG TPM Simulator
FROM alpine:latest AS builder
RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    openssl-dev \
    rust \
    cargo \
    tpm2-tss-dev \
    tpm2-tss-esys \
    tpm2-tss-tctildr

WORKDIR /app
RUN git clone https://github.com/TrustedComputingGroup/TPM.git && \
    cd /app/TPM/TPMCmd && \
    mkdir -p build && \
    cmake -S . -B ./build/ -G "Unix Makefiles" && \
    cmake --build build/

WORKDIR /app/tpm_provisioner
COPY . .
RUN cargo build --release

# Runtime environment of tpm provisioner
FROM alpine:latest AS runner

RUN apk add --no-cache \
    bash \
    openssl \
    tpm2-tss \
    tpm2-tools \
    tpm2-tss-tcti-mssim \
    libgcc

WORKDIR /app/tpm_provisioner

COPY entrypoint.sh verify.sh ./

RUN chmod +x entrypoint.sh verify.sh && \
    mv entrypoint.sh /usr/local/bin/ && \
    mv verify.sh /usr/local/bin/verify

COPY --from=builder /app/tpm_provisioner/target/release/tpm_provisioner /usr/local/bin/tpm_provisioner
RUN mkdir -p /app/TPM/TPMCmd/build/Simulator
COPY --from=builder /app/TPM/TPMCmd/build/Simulator/Simulator /app/TPM/TPMCmd/build/Simulator/Simulator

#ENV TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=2321"

ENTRYPOINT ["entrypoint.sh"]
CMD ["/bin/bash"]