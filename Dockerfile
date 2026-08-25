FROM mirror.gcr.io/library/golang@sha256:e6e8ff4b72b128bb673613645c5ac415e4f537b2390e77a86ffc40622ab56da8 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/tikti ./cmd/tikti
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/tikti-bootstrap ./cmd/tikti-bootstrap

FROM mirror.gcr.io/library/alpine@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app
COPY --from=builder /out/tikti /app/tikti
COPY --from=builder /out/tikti-bootstrap /app/tikti-bootstrap
RUN chmod +x /app/tikti /app/tikti-bootstrap
USER 65532:65532
EXPOSE 8080
CMD ["/app/tikti"]
