FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS orchestrator-builder

# The compiler image is digest-pinned. Only the compiled binary and its CA
# bundle (used to bootstrap HTTPS for apt) are copied into runtime.

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /measure-image ./cmd/measure-image

FROM ubuntu@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

# Noble reads deb822 sources from ubuntu.sources. Replace that file rather than
# adding a legacy sources.list alongside the moving default repositories.
COPY --from=orchestrator-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN printf '%s\n' \
      'Types: deb' \
      'URIs: https://snapshot.ubuntu.com/ubuntu/20260820T000000Z' \
      'Suites: noble noble-updates noble-security' \
      'Components: main restricted universe multiverse' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/ubuntu.sources && \
    rm -f /etc/apt/sources.list

WORKDIR /app
COPY requirements.txt /
RUN mkdir -p /output /cache

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl python3 python3-venv && \
    rm -rf /var/lib/apt/lists/*

# Download and verify GitHub CLI binary
RUN curl -L https://github.com/cli/cli/releases/download/v2.67.0/gh_2.67.0_linux_amd64.tar.gz -o gh.tar.gz && \
    echo "d77623479bec017ef8eebadfefc785bafd4658343b3eb6d3f3e26fd5e11368d5  gh.tar.gz" | sha256sum -c - && \
    tar -xzf gh.tar.gz && \
    mv gh_2.67.0_linux_amd64/bin/gh /usr/local/bin/gh && \
    rm -rf gh.tar.gz gh_2.67.0_linux_amd64

# Download and verify tdx-measure binary
RUN curl -L https://github.com/tinfoilsh/tdx-measure/releases/download/v0.0.6/tdx-measure -o tdx-measure && \
    echo "d1bde7b36bdc6437140478428127809f16ac8f024cd08007a05ccdaa4044309e  tdx-measure" | sha256sum -c - && \
    chmod +x tdx-measure

# Download and verify boot-shim binary
RUN curl --fail --proto '=https' -L https://github.com/tinfoilsh/boot-shim/releases/download/v0.1.0/boot-shim -o boot-shim && \
    echo "acedc9df0c116e860418b52da8c186412017d420430c881e81f0365319108fb2  boot-shim" | sha256sum -c - && \
    chmod +x boot-shim

# sev-snp-measure remains an independently pinned external measurement tool.
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --require-hashes -r /requirements.txt

COPY --from=orchestrator-builder /measure-image /usr/local/bin/measure-image

ENTRYPOINT ["/usr/local/bin/measure-image"]
