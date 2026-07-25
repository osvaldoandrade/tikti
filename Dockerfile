FROM mirror.gcr.io/library/golang:1.25@sha256:9006890ecba0a168034d99516084099ae3114d9f2b7d6572c77f2dde57ebc980 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/tikti ./cmd/tikti
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/tikti-bootstrap ./cmd/tikti-bootstrap

FROM alpine:3.18@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app
COPY --from=builder /out/tikti /app/tikti
COPY --from=builder /out/tikti-bootstrap /app/tikti-bootstrap
RUN chmod +x /app/tikti
EXPOSE 8080
USER 65532:65532
CMD ["/app/tikti"]
