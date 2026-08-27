# Multi-stage build for leakscan
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/leakscan main.go

# Minimal runtime image
FROM alpine:3.20

RUN apk add --no-cache git ca-certificates tzdata && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /scan

COPY --from=builder /app/leakscan /usr/local/bin/leakscan

USER appuser

ENTRYPOINT ["leakscan"]
CMD ["scan", "."]
