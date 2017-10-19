FROM rust:latest

WORKDIR /build
COPY . /build/

RUN mkdir -p /app && cargo install --root=/app
