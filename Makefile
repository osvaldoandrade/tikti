IMAGE_NAME ?= tikti
IMAGE_TAG ?= dev
IMAGE_URI ?= $(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: build docker-build docker-push lint

build:
	go build -o bin/tikti ./cmd/tikti

docker-build:
	docker build -t $(IMAGE_URI) .

docker-push:
	@echo "Set IMAGE_URI to your registry target" && docker push $(IMAGE_URI)

lint:
	go vet ./...
