#!/usr/bin/env python3
"""
Secret detector + secret-list builder for the redacting proxy.

Takes the strings REA pulled from the binary (out/raw/strings.json, written by
pipeline/01_extract.sh), applies a deterministic rule-based detector (high
precision) to decide which strings are secrets and what type they are, and writes:

  out/secrets_raw.json       -> the list for the proxy: [{value,type,opaque}]
  out/secret_inventory.json  -> masked inventory (found vs ground truth)

GROUND_TRUTH below lists the 7 secrets of syncd only to score found vs missed:
the 4 top-level secrets plus the database user, password and host embedded in
the connection string. This file therefore holds the secrets in clear text:
keep it (like target/syncd.c) out of the agent's reach.
"""
import json, os, re, sys

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "..", "out")
RAW = os.path.join(OUT, "raw")

GROUND_TRUTH = [
    {"value": "r3quest-signing-seed::9b2f.KX", "type": "signing_key"},
    {"value": "sync-gw.internal.corp.local", "type": "hostname"},
    {"value": "HIT-7f3a9c21b8e4d6f05a1c-REQSIGN", "type": "api_key"},
    {"value": "postgresql://syncd_svc:Pr0d-Sync!2019_dbx@db-internal.corp.local:5432/records",
     "type": "connection_string"},
    # embedded in the connection string, listed as secrets of their own
    {"value": "syncd_svc", "type": "db_user"},
    {"value": "Pr0d-Sync!2019_dbx", "type": "password"},
    {"value": "db-internal.corp.local", "type": "db_host"},
]

def mask(v):
    if len(v) <= 6:
        return "*" * len(v)
    return v[:3] + "*" * (len(v) - 6) + v[-3:]

def classify(s):
    """Return (type, extra_values_to_also_mask) or (None, [])."""
    # connection string with embedded credentials
    m = re.match(r"^([a-z0-9+]+)://([^:/@\s]+):([^@/\s]+)@([^/:\s]+)", s)
    if m:
        user, pw, host = m.group(2), m.group(3), m.group(4)
        return "connection_string", [pw, user, host]
    # api key / signing token: FICTIONAL prefix + long hex-ish body, no spaces
    if re.match(r"^[A-Z][A-Za-z0-9]{1,6}-[0-9a-fA-F]{12,}", s) and " " not in s:
        return "api_key", []
    # signing seed / opaque key: has separator punctuation + mixed case + digits, no spaces, len>=12
    if (" " not in s and len(s) >= 12 and re.search(r"[A-Za-z]", s) and re.search(r"\d", s)
            and re.search(r"[:._\-]{1,}", s) and not s.startswith((".", "/", "%", "_"))
            and "GLIBC" not in s and ".so" not in s):
        return "signing_key", []
    # internal hostname
    if re.search(r"\.(internal|corp|intra|local)(\b|$)", s) and " " not in s and "/" not in s:
        return "hostname", []
    return None, []

def main():
    raw = json.load(open(os.path.join(RAW, "strings.json")))
    strings = [x["value"] for x in raw["normalized_result"]]

    found = []
    mask_set = {}  # value -> type
    for s in strings:
        typ, extra = classify(s)
        if not typ:
            continue
        mask_set[s] = typ
        for e in extra:
            # embedded password/user/host: masked under the parent type
            # (the password gets type "password" in secrets_raw.json below)
            mask_set.setdefault(e, "connection_string")
        found.append({
            "value_masked": mask(s),
            "type": typ,
        })

    # secrets_raw.json for the proxy: the REAL secret strings
    # with an `opaque` flag. The hash seed (first 4 key bytes) needs no entry:
    # the proxy masks every 4-byte window of the key in hex, numeric and base64
    # form. High-entropy secrets (signing key, api key, password)
    # are opaque -> even their >=5-char text windows are masked; low-entropy
    # secrets (hostnames, usernames with dictionary words) rely on full-value +
    # byte-window masking so we don't redact benign tokens like "sync" or "local".
    OPAQUE_TYPES = {"signing_key", "api_key", "password"}
    # the embedded db password is high-entropy -> treat as opaque
    opaque_values = set()
    for v, t in mask_set.items():
        if t == "connection_string":
            m2 = re.match(r"^[a-z0-9+]+://([^:/@\s]+):([^@/\s]+)@", v)
            if m2:
                opaque_values.add(m2.group(2))  # the password
    secrets_raw = []
    for v, t in sorted(mask_set.items(), key=lambda kv: -len(kv[0])):
        opaque = (t in OPAQUE_TYPES) or (v in opaque_values)
        secrets_raw.append({"value": v, "type": ("password" if v in opaque_values else t), "opaque": opaque})
    json.dump(secrets_raw, open(os.path.join(OUT, "secrets_raw.json"), "w"), indent=1)

    # Score found vs ground truth
    gt_values = {g["value"] for g in GROUND_TRUTH}
    found_values = set(mask_set.keys())
    hits = gt_values & found_values
    missed = gt_values - found_values
    # false alarms: detector hits that are not ground-truth secrets and not
    # substrings of a ground-truth secret
    false_alarms = []
    for v in found_values:
        if v in gt_values:
            continue
        if any(v in g for g in gt_values):  # embedded (db user/pass/host) - legitimate
            continue
        false_alarms.append(mask(v))

    inventory = {
        "ground_truth_count": len(GROUND_TRUTH),
        "found_count": len(hits),
        "missed_count": len(missed),
        "false_alarms": false_alarms,
        "found": sorted(mask(v) for v in hits),
        "missed": sorted(mask(v) for v in missed),
        "findings": found,
    }
    json.dump(inventory, open(os.path.join(OUT, "secret_inventory.json"), "w"), indent=1)
    print(json.dumps({k: inventory[k] for k in
          ("ground_truth_count", "found_count", "missed_count", "false_alarms")}, indent=1))
    print(f"secrets_raw.json: {len(secrets_raw)} values (out/secrets_raw.json)")

if __name__ == "__main__":
    main()
