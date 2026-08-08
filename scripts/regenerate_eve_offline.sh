#!/usr/bin/env bash
set -euo pipefail

# Optional only. Normal imports and CI consume fixtures/suricata/eve.jsonl.
# Select an authoritative Suricata image by immutable digest before use:
#   SURICATA_IMAGE_REF='registry.example/suricata@sha256:<64 lowercase hex>'
: "${SURICATA_IMAGE_REF:?set a digest-pinned Suricata image reference}"
if [[ ! "$SURICATA_IMAGE_REF" =~ @sha256:[0-9a-f]{64}$ ]]; then
  echo "refused: image must be pinned by sha256 digest" >&2
  exit 2
fi

test -r evidence/private/telemetry/input.pcap
test -r fixtures/suricata/regeneration/suricata.yaml
mkdir -p evidence/private/telemetry/regenerated
test -z "$(find evidence/private/telemetry/regenerated -mindepth 1 -maxdepth 1 -print -quit)"

timeout 300 docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 1g \
  --cpus 2 \
  --tmpfs /tmp:size=64m,mode=1777 \
  -v "$PWD/evidence/private/telemetry/input.pcap:/input/input.pcap:ro" \
  -v "$PWD/fixtures/suricata/regeneration/suricata.yaml:/config/suricata.yaml:ro" \
  -v "$PWD/evidence/private/telemetry/regenerated:/output:rw" \
  "$SURICATA_IMAGE_REF" \
  -c /config/suricata.yaml -r /input/input.pcap -l /output
