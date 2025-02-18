# Build stage using an official Go image.
FROM golang:1.20 AS builder

WORKDIR /app

# Copy the source code and directories.
COPY . .

# Ensure that the "ssl" and "webroot" directories exist.
RUN mkdir -p ssl webroot

# If no go.mod file exists, initialize a Go module.
RUN if [ ! -f go.mod ]; then \
      go mod init github.com/yourusername/dynamic_mitm_server; \
    fi && \
    go mod tidy

# Build the binary.
RUN CGO_ENABLED=0 go build -o dynamic_mitm_server .

# Final minimal image.
FROM alpine:latest

WORKDIR /root/

# Copy the binary and the ssl & webroot directories.
COPY --from=builder /app/dynamic_mitm_server .
COPY --from=builder /app/ssl ./ssl
COPY --from=builder /app/webroot ./webroot

# Expose the port (default 443).
EXPOSE 443

ENTRYPOINT ["./dynamic_mitm_server"]
