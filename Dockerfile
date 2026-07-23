FROM mirror.gcr.io/library/golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/tikti ./cmd/tikti
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/tikti-bootstrap ./cmd/tikti-bootstrap

FROM alpine:3.18
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app
COPY --from=builder /out/tikti /app/tikti
COPY --from=builder /out/tikti-bootstrap /app/tikti-bootstrap
RUN chmod +x /app/tikti
EXPOSE 8080
CMD ["/app/tikti"]
