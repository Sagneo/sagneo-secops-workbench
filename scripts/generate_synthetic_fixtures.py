"""Generate the reviewed deterministic synthetic fixtures.

This script has no network input. It writes only the exact tracked fixture targets.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINUX = ROOT / "fixtures/linux/auth.log"
EVE = ROOT / "fixtures/suricata/eve.jsonl"
LINUX_BAD = ROOT / "fixtures/linux/auth-malformed.log"
EVE_BAD = ROOT / "fixtures/suricata/eve-malformed.jsonl"
MANIFEST = ROOT / "fixtures/expected/telemetry-manifest.json"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    linux_lines: list[str] = []
    linux_start = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    for index in range(600):
        timestamp = (linux_start + timedelta(seconds=index)).isoformat()
        if index % 5 == 0:
            message = (
                f"synth-admin-{index % 4} : TTY=pts/0 ; PWD=/srv/lab ; "
                "USER=root ; COMMAND=/usr/bin/id"
            )
            linux_lines.append(f"{timestamp} linux-endpoint-01 sudo: {message}")
        else:
            verb = "Accepted" if index % 11 == 0 else "Failed"
            actor = f"synth-user-{index % 20:02d}"
            source_ip = f"192.0.2.{10 + (index % 200)}"
            linux_lines.append(
                f"{timestamp} linux-endpoint-01 sshd[{2000 + index}]: "
                f"{verb} password for {actor} from {source_ip} port {40000 + index} ssh2"
            )
    _write_lines(LINUX, linux_lines)

    plus_two = timezone(timedelta(hours=2))
    eve_start = datetime(2026, 7, 24, 14, 30, tzinfo=plus_two)
    eve_lines: list[str] = []
    for index in range(600):
        record: dict[str, object] = {
            "timestamp": (eve_start + timedelta(seconds=index)).isoformat(),
            "flow_id": 900000 + index,
            "event_type": "alert" if index % 3 == 0 else "flow",
            "src_ip": f"192.0.2.{20 + (index % 180)}",
            "src_port": 20000 + index,
            "dest_ip": "192.168.90.20",
            "dest_port": 22 if index % 2 == 0 else 443,
            "proto": "TCP",
        }
        if record["event_type"] == "alert":
            record["alert"] = {
                "signature_id": 2200000 + (index % 5),
                "signature": f"SYNTHETIC LAB network pattern {index % 5}",
                "category": "Synthetic lab activity",
                "severity": 1 if index % 6 == 0 else 3,
            }
        eve_lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
    _write_lines(EVE, eve_lines)

    _write_lines(
        LINUX_BAD,
        [
            "2026-07-24T13:15:00Z linux-endpoint-01 sshd[9991]: "
            "Failed password for synth-error-user from 192.0.2.240 port 49991 ssh2",
            "not a bounded Linux authentication record",
            "2026-07-24T13:15:02Z linux-endpoint-01 sshd[9992]: missing required fields",
        ],
    )
    valid_error_eve = {
        "timestamp": "2026-07-24T13:16:00Z",
        "flow_id": 9999001,
        "event_type": "flow",
        "src_ip": "192.0.2.241",
        "dest_ip": "192.168.90.20",
        "proto": "TCP",
    }
    _write_lines(
        EVE_BAD,
        [
            json.dumps(valid_error_eve, sort_keys=True, separators=(",", ":")),
            "{not-json",
            json.dumps(
                {
                    "event_type": "flow",
                    "src_ip": "192.0.2.242",
                    "dest_ip": "192.168.90.20",
                    "proto": "TCP",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        ],
    )

    manifest = {
        "fixture_set": "synthetic-auth-eve-v1",
        "parser_version": "1.0.0",
        "provenance": "deterministic synthetic records generated locally without network input",
        "files": {
            "fixtures/linux/auth.log": {
                "sha256": _digest(LINUX),
                "records": 600,
                "accepted": 600,
                "errors": 0,
            },
            "fixtures/suricata/eve.jsonl": {
                "sha256": _digest(EVE),
                "records": 600,
                "accepted": 600,
                "errors": 0,
            },
            "fixtures/linux/auth-malformed.log": {
                "sha256": _digest(LINUX_BAD),
                "records": 3,
                "accepted": 1,
                "errors": 2,
            },
            "fixtures/suricata/eve-malformed.jsonl": {
                "sha256": _digest(EVE_BAD),
                "records": 3,
                "accepted": 1,
                "errors": 2,
            },
        },
        "main_unique_events": 1200,
        "assets": 2,
        "source_types": ["LINUX_AUTH", "SURICATA_EVE"],
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
