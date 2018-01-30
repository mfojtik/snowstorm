all: build
.PHONY: all
SHELL := /bin/bash
DOCKER_REPO ?= docker.io/mfojtik/snowstorm

build_linux_cmd = mkdir -p _output/amd64 && GOOS=linux go build -o _output/amd64/$(1) ./cmd/$(1)
build_cmd = mkdir -p _output && go build -o _output/$(1) ./cmd/$(1)

build-linux:
		$(call build_linux_cmd,snowstorm)
.PHONY: build

build:
		$(call build_cmd,snowstorm)
.PHONY: build

build-image: build-linux
	docker build -t $(DOCKER_REPO) .
.PHONY: build-image

push-image: build-image
	docker push $(DOCKER_REPO):latest

clean:
	rm -rf _output
.PHONY: clean

update-deps:
	glide update --strip-vendor
.PHONY: update-deps
