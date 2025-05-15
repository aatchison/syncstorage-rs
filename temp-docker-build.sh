#!/usr/bin/env bash
docker build --build-arg DATABASE_BACKEND="mysql"  -t app:build .
docker tag app:build syncstorage-rs:latest