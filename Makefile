all: check build test

export RUSTFLAGS=-Dwarnings -Dclippy::all -Dclippy::pedantic

build:
	cargo clippy --all-targets

test:
	cargo test

fmt:
	cargo fmt --all

clean:
	cargo clean
	go clean ./...

.PHONY: all build test fmt clean
