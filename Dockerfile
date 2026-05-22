FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mitm-blockpage .

FROM alpine:3.23.4

RUN addgroup -S app \
    && adduser -S -G app app \
    && mkdir -p /app/ssl /app/webroot \
    && chown -R app:app /app

WORKDIR /app

COPY --from=builder /out/mitm-blockpage ./mitm-blockpage
COPY --chown=app:app webroot ./webroot

ENV LISTEN_ADDR=0.0.0.0 \
    LISTEN_PORT=8443 \
    BLOCK_PAGE_PATH=/app/webroot/block.html \
    WEBROOT_DIR=/app/webroot

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-check-certificate -qO- https://127.0.0.1:8443/healthz >/dev/null || exit 1

USER app

ENTRYPOINT ["./mitm-blockpage"]
