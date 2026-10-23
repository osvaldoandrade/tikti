FROM mirror.gcr.io/library/golang:1.26.10-trixie@sha256:909771fef53e3dcb0950255f0c9a8b4728c3b841e61509c7b29b098de7ee02d4 AS builder
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
