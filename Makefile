all: check build test

export RUSTFLAGS=-Dwarnings -Dclippy::all -Dclippy::pedantic

build:
	cargo build

check:
	cargo clippy --all-targets

test:
	cargo test

fmt:
	cargo fmt --all

clean:
	cargo clean
	go clean ./...

.PHONY: all build test fmt clean
