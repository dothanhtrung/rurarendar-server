#!/usr/bin/env just --justfile

css:
    cd server && npx @tailwindcss/cli -i ./templates/css/tailwind_input.css -o ./templates/css/tailwind_output.min.css --minify

linux-arm64:
    cargo build --release --target=aarch64-unknown-linux-gnu

watch:
    bacon run-long -- -- -c ./rurarendar-server.ron
