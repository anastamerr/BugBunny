#!/usr/bin/env bash
set -euo pipefail

base_url="${ZAP_BASE_URL:-}"
host_port="${ZAP_HOST_PORT:-}"
host_header="${ZAP_HOST_HEADER:-}"

if [[ -z "$base_url" ]]; then
  if [[ -n "$host_port" ]]; then
    base_url="http://127.0.0.1:${host_port}"
  else
    base_url="http://127.0.0.1:8080"
  fi
fi

if [[ -z "$host_header" ]]; then
  if [[ "$base_url" =~ 127\.0\.0\.1:([0-9]+) ]]; then
    port="${BASH_REMATCH[1]}"
    if [[ "$port" != "8080" ]]; then
      host_header="127.0.0.1:8080"
    fi
  fi
fi

echo "Base URL: ${base_url}"
if [[ -n "$host_header" ]]; then
  echo "Host header: ${host_header}"
  echo "curl -H \"Host: ${host_header}\" \"${base_url}/JSON/core/view/version/\""
else
  echo "curl \"${base_url}/JSON/core/view/version/\""
fi
