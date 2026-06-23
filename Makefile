SHELL := /bin/sh

.PHONY: test fmt check up up-test down run migrate

test:
	cargo test

fmt:
	cargo fmt

check:
	cargo check

run:
	cargo run --bin imap-cache-rs

migrate:
	cargo run --bin imap-cache-rs -- run-migrations

up:
	docker compose up --build

up-test:
	docker compose --profile test up --build

down:
	docker compose down -v
