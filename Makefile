IMAGE_NAME ?= tikti
IMAGE_TAG ?= dev
IMAGE_URI ?= $(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: build docker-build docker-push lint test helm-test fuzz-object-storage

test:
	go test ./...

helm-test:
	bash hack/test-storage-sts-chart.sh

fuzz-object-storage:
	go test ./internal/storagests -run '^$$' -fuzz '^FuzzAdministrativeListXMLShapeNeverPanics$$' -fuzztime=10s
	go test ./internal/storagests -run '^$$' -fuzz '^FuzzAdministrativeSigV4PresignRemainsKeyBound$$' -fuzztime=10s

build:
	go build -o bin/tikti ./cmd/tikti

docker-build:
	docker build -t $(IMAGE_URI) .

docker-push:
	@echo "Set IMAGE_URI to your registry target" && docker push $(IMAGE_URI)

lint:
	go vet ./...

.PHONY: saml-dev saml-integration saml-keys

saml-keys:
	openssl req -x509 -newkey rsa:2048 -keyout hack/saml/sp.key -out hack/saml/sp.crt \
	  -nodes -days 365 -subj "/CN=tikti-sp"

saml-dev: saml-keys
	docker compose -f hack/saml/docker-compose.yaml up --build

saml-integration:
	go test -count=1 ./test/integration -run TestSAMLE2E
