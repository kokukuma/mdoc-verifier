all: run

.PHONY: run
run:
	go run -mod=vendor cmd/server/server.go &
	go run cmd/client/client.go

.PHONY: ngrok
ngrok:
	ngrok start --all
