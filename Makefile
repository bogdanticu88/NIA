.PHONY: build vet test run-api run-gateway up down

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

run-api:
	go run ./cmd/api

run-gateway:
	go run ./cmd/gateway

up:
	docker compose -f deployments/docker-compose.yml up -d

down:
	docker compose -f deployments/docker-compose.yml down
