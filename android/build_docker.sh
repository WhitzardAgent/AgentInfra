#!/usr/bin/env bash
set -e

IMG=${IMG:-android-with-mcp:11}
NO_CACHE=${NO_CACHE:-0}   # 想强制干净重建：NO_CACHE=1 ./build_docker.sh

if [[ "$NO_CACHE" == "1" ]]; then
  echo "[build] building (no cache) $IMG ..."
  docker build --no-cache -t "$IMG" .
else
  echo "[build] building $IMG ..."
  docker build -t "$IMG" .
fi

echo "[build] done: $IMG"
