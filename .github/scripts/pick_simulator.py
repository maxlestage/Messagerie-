#!/usr/bin/env python3
"""Choisit un simulateur iPhone disponible et imprime son UDID.

Le nom des simulateurs pré-installés change d'une image de runner GitHub à
l'autre (« iPhone 15 », « iPhone 16 »…). Mettre un nom en dur dans le workflow
le casserait à la prochaine mise à jour d'image : on prend donc le simulateur
iPhone le plus récent réellement présent.

Usage :  python3 .github/scripts/pick_simulator.py   (nécessite xcrun, macOS)
"""

import json
import subprocess
import sys


def main() -> int:
    raw = subprocess.run(
        ["xcrun", "simctl", "list", "devices", "available", "--json"],
        capture_output=True, text=True, check=True,
    ).stdout

    best = None  # (runtime, udid, nom) — le runtime le plus grand l'emporte.
    for runtime, devices in sorted(json.loads(raw)["devices"].items()):
        if "iOS" not in runtime:
            continue
        for device in devices:
            if device.get("isAvailable") and "iPhone" in device.get("name", ""):
                best = (runtime, device["udid"], device["name"])

    if best is None:
        print("::error::Aucun simulateur iPhone disponible sur ce runner.",
              file=sys.stderr)
        return 1

    runtime, udid, name = best
    print(f"Simulateur retenu : {name} ({runtime})", file=sys.stderr)
    print(udid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
