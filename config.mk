BINARY_NAME ?= $(notdir $(CURDIR))
GOOS ?= linux
GOARCH ?= amd64
OUTPUT_DIR ?= bin/$(GOOS)/$(GOARCH)
