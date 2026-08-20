FROM golang:1.25.7-bookworm@sha256:58259daf0a27c150118663ef7452aa94d66a86d55e73b3443386146623f5364d AS config-validator-builder

# The compiler image is digest-pinned and never copied into runtime.

WORKDIR /validator
COPY validator/go.mod validator/go.sum ./
RUN go mod download
COPY validator/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tinfoil-config-validator .

FROM ubuntu@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

# Pin apt packages to a specific Ubuntu snapshot for reproducibility
RUN echo "deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/20250107T000000Z noble main restricted universe multiverse" > /etc/apt/sources.list && \
    echo "deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/20250107T000000Z noble-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/20250107T000000Z noble-security main restricted universe multiverse" >> /etc/apt/sources.list

WORKDIR /app
COPY *.py requirements.txt /
RUN mkdir -p /output /cache

RUN apt-get update && apt-get install -y ca-certificates curl python3 python3-venv

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

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --require-hashes -r /requirements.txt

COPY --from=config-validator-builder /tinfoil-config-validator /usr/local/bin/tinfoil-config-validator

ENTRYPOINT ["/opt/venv/bin/python", "/measure.py"]
