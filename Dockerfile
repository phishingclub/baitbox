# development docker file
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b

WORKDIR /app

# add user with id 1000 to match the host bind mount owner
RUN groupadd -g 1000 appuser && \
    useradd -r -u 1000 -g appuser appuser -d /home/appuser -m

COPY go.mod /app/go.mod
RUN mkdir -p /app/.dev /app/.dev-air && chown -R appuser:appuser /app

USER appuser
RUN go install github.com/cosmtrek/air@v1.40.4

CMD ["air", "-c", "/app/.air.toml"]
