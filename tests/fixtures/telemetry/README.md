# Synthetic Sprint 2 telemetry fixtures

These files are fabricated metadata-only records for parser and contract tests. They contain
documentation address ranges and no captured payloads, credentials, dataset material, or real
network context. Oversized inputs and PCAP bytes are generated in temporary test directories so
large files and PCAP artifacts are never committed.

Coverage includes valid canonical flow JSONL, duplicate identity, out-of-order timestamps,
malformed/truncated JSON, Unicode rejection, Zeek `conn.log`, Suricata EVE flow records, and an
unsupported Suricata alert that must remain deferred to Sprint 3.
