all: build
.PHONY: all
SHELL := /bin/bash
DOCKER_REPO ?= docker.io/mfojtik/snowstorm

build_cmd = mkdir -p _output && GOOS=linux go build -o _output/$(1) ./cmd/$(1)

build:
		$(call build_cmd,snowstorm)
.PHONY: build

build-image: build
	docker build -t $(DOCKER_REPO) .
.PHONY: build-image

push-image:
	docker push $(DOCKER_REPO):latest

clean:
	rm -rf _output
.PHONY: clean

update-deps:
	glide update --strip-vendor
.PHONY: update-deps
