#!/usr/bin/env python3
"""Assert a vens VEX file is valid *and scored*.

Used by .github/workflows/nightly-llm-smoke.yml after `vens generate`
runs against a real LLM provider: a response-format change on the provider
side shows up here as a missing or unscored vulnerability.
"""

import json
import sys


def main(path: str) -> None:
    with open(path) as f:
        bom = json.load(f)

    assert bom.get("bomFormat") == "CycloneDX", (
        f"bomFormat is {bom.get('bomFormat')!r}, not CycloneDX"
    )
    vulns = bom.get("vulnerabilities") or []
    assert vulns, "VEX contains no vulnerabilities"

    for v in vulns:
        vid = v.get("id", "<unknown>")
        ratings = v.get("ratings") or []
        assert ratings, f"vulnerability {vid} has no ratings"
        assert any(
            isinstance(r.get("score"), (int, float)) for r in ratings
        ), f"vulnerability {vid} has no numeric score"

    print(f"OK: {path} is a valid scored VEX ({len(vulns)} vulnerabilities)")


if __name__ == "__main__":
    main(sys.argv[1])
