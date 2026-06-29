# AEP output-binding feasibility demo — portable container.
# A minimal Debian base with a software TPM (swtpm) + tpm2-tools + openssl,
# so the demo runs identically on any laptop with Docker, no host TPM needed.
FROM debian:bookworm-slim

# swtpm        -> the software TPM emulator (Attester stand-in)
# swtpm-tools  -> swtpm helper binaries
# tpm2-tools   -> tpm2_startup/quote/checkquote/pcrextend/createek/createak/...
# openssl      -> fresh nonces (openssl rand)
# coreutils    -> sha256sum, cmp, mktemp (already present, listed for clarity)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        swtpm swtpm-tools tpm2-tools openssl ca-certificates coreutils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /demo
COPY run_pipeline.sh /demo/run_pipeline.sh
COPY demo.aep.json   /demo/demo.aep.json
RUN chmod +x /demo/run_pipeline.sh

# Write artefacts into a world-writable dir so the script can run as any UID
# (e.g. `docker run --user $(id -u)`); default writes go next to the script.
ENTRYPOINT ["/demo/run_pipeline.sh"]
CMD ["/demo"]
