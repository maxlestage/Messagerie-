#!/usr/bin/env python3
"""Vérifie que project.yml et Brocolis.xcodeproj décrivent le MÊME projet.

`project.yml` est présenté (README, docs/XCODE_CLOUD.md) comme la source de
vérité : `xcodegen generate` réécrit le pbxproj à partir de lui. Quand une cible
existe dans le pbxproj mais pas dans le spec, une simple régénération la
supprime — sans erreur ni avertissement. C'est arrivé à l'app montre
(`BrocolisWatch`), restée absente de project.yml après son ajout.

Ce contrôle compare deux choses volontairement grossières mais impossibles à
faire diverger par accident : le NOM des cibles, et l'ensemble des identifiants
de bundle. Il ne cherche pas à comparer chaque réglage — ce serait fragile, et
ce n'est pas là que le projet dérive silencieusement.

Usage :  python3 .github/scripts/check_project_spec.py
"""

import re
import sys
import pathlib

try:
    import yaml
except ImportError:
    sys.exit("pyyaml manquant : pip install pyyaml")

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = ROOT / "project.yml"
PBX = ROOT / "Brocolis.xcodeproj" / "project.pbxproj"


def spec_targets() -> tuple[set[str], set[str]]:
    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    targets = doc.get("targets") or {}
    bundles = set()
    for target in targets.values():
        base = ((target.get("settings") or {}).get("base") or {})
        bundle = base.get("PRODUCT_BUNDLE_IDENTIFIER")
        if bundle:
            bundles.add(str(bundle))
    return set(targets), bundles


def pbx_targets() -> tuple[set[str], set[str]]:
    text = PBX.read_text(encoding="utf-8")
    section = text.split("/* Begin PBXNativeTarget section */")[1] \
                  .split("/* End PBXNativeTarget section */")[0]
    names = {n.strip().strip('"')
             for n in re.findall(r"^\t\t\tname = (.+);$", section, re.M)}
    bundles = set(re.findall(r"PRODUCT_BUNDLE_IDENTIFIER = ([^;]+);", text))
    return names, {b.strip().strip('"') for b in bundles}


def report(label: str, in_spec: set[str], in_pbx: set[str]) -> bool:
    ok = True
    for missing in sorted(in_pbx - in_spec):
        ok = False
        print(f"::error file=project.yml::{label} « {missing} » est dans "
              f"Brocolis.xcodeproj mais absent de project.yml — un "
              f"`xcodegen generate` le supprimerait du projet.")
    for extra in sorted(in_spec - in_pbx):
        ok = False
        print(f"::error file=project.yml::{label} « {extra} » est dans "
              f"project.yml mais absent de Brocolis.xcodeproj — le projet "
              f"committé n'a pas été régénéré.")
    return ok


def main() -> int:
    spec_names, spec_bundles = spec_targets()
    pbx_names, pbx_bundles = pbx_targets()

    ok = report("La cible", spec_names, pbx_names)
    ok &= report("L'identifiant de bundle", spec_bundles, pbx_bundles)

    if ok:
        print(f"project.yml et Brocolis.xcodeproj concordent "
              f"({len(spec_names)} cibles, {len(spec_bundles)} bundles).")
        return 0
    print("\nCorrige project.yml (ou régénère le projet avec "
          "`xcodegen generate`) pour que les deux concordent.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
