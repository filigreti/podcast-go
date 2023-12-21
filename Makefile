.PHONY: build run

build:
	@go build -o ./bin/go-podcast ./cmd

run: build
	@./bin/go-podcast 
