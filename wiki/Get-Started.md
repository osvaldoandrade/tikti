# Get Started

This page is the fastest way to run Tikti locally and validate the core identity flows.

## Prerequisites

- Go 1.24+
- Redis reachable from Tikti (`redisAddr` in config)
- A local config file, typically `config/tikti.yaml`

## Run Tikti

```bash
go run ./cmd/tikti -f config/tikti.yaml
```

## Build Binaries

```bash
go build -o tikti ./cmd/tikti
go build -o tikti-cli ./cmd/tikti-cli
go build -o tikti-migrate ./cmd/tikti-migrate
```

## Core Authentication Flow

1. Frontend calls `POST /v1/accounts/sendOobCode?key=...` with user email and requestType.
2. Tikti creates user when needed and emits an OOB code flow per spec.
3. User receives the token and submits it to `POST /v1/accounts/signInWithOobCode`.
4. Tikti validates OOB code and returns authentication tokens.

## Useful Next Pages

- [API Specification](API-Specification)
- [Tokens and Keys](Tokens-and-Keys)
- [codeQ Integration](codeQ-Integration)
- [Operations and SLO](Operations-and-SLO)
