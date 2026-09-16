#!/usr/bin/env bash
# Creates an OpenFGA store and loads the authorization model this stack
# needs. OpenFGA doesn't come preconfigured with either, and that has to
# happen against a running instance, not baked into docker-compose.yml,
# which is why TESSERA_OPENFGA_STORE_ID has no default there, see that
# file's own top comment.
#
# Run this after postgres and openfga are up but before bringing up the
# rest of the stack:
#
#   docker compose up -d postgres openfga
#   ./bootstrap-openfga.sh
#
# It prints the line to add to .env, then bring up everything else:
#
#   echo "TESSERA_OPENFGA_STORE_ID=<the id it printed>" >> .env
#   docker compose up -d --build
#
# The model shape here (client, api_group with a member relation,
# api_endpoint with one relation per HTTP method) matches what
# GrantTupleMapper in Tessera.ControlPlane actually writes, see
# tessera's README, "Declared intent maps to OpenFGA tuples as follows".
# It was worked out and confirmed by hand against a live OpenFGA
# instance, onboarding a test client and checking the resulting tuple,
# then killing it and confirming the tuple was actually gone, not
# written from documentation alone.
set -euo pipefail

OPENFGA_URL="${OPENFGA_URL:-http://localhost:8082}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "creating store against $OPENFGA_URL..." >&2
STORE_RESPONSE=$(curl -sf -X POST "$OPENFGA_URL/stores" -H "Content-Type: application/json" -d '{"name":"tessera"}')
STORE_ID=$(echo "$STORE_RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "store id: $STORE_ID" >&2

echo "loading authorization model..." >&2
MODEL_RESPONSE=$(curl -sf -X POST "$OPENFGA_URL/stores/$STORE_ID/authorization-models" \
  -H "Content-Type: application/json" -d @"$SCRIPT_DIR/openfga-model.json")
MODEL_ID=$(echo "$MODEL_RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["authorization_model_id"])')
echo "authorization model id: $MODEL_ID" >&2

echo "" >&2
echo "add this to .env, then bring up the rest of the stack:" >&2
echo "TESSERA_OPENFGA_STORE_ID=$STORE_ID"
