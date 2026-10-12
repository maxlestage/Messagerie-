#!/usr/bin/env python3
"""Règle Xcode Cloud via l'API App Store Connect (clé ASC_* des secrets GitHub).

Tout workflow Xcode Cloud qui ARCHIVE est DÉSACTIVÉ : la seule livraison
TestFlight est celle de GitHub Actions (10000+). Le passage en démarrage
manuel ne suffisait pas (Xcode Cloud lançait encore un build par poussée).
Pour le réactiver un jour : App Store Connect → Xcode Cloud → le workflow →
Enable, avec BROCOLIS_XCODE_CLOUD_UPLOAD=1 dans ses variables.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

import jwt

BUNDLE_ID = os.environ.get("BUNDLE_ID", "rs.brocolis.messagerie")
API = "https://api.appstoreconnect.apple.com"


def token():
    now = int(time.time())
    return jwt.encode(
        {"iss": os.environ["ASC_ISSUER_ID"], "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"},
        os.environ["ASC_KEY_P8"],
        algorithm="ES256",
        headers={"kid": os.environ["ASC_KEY_ID"], "typ": "JWT"},
    )


def call(method, path, body=None):
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        print(f"::error::{method} {path} → {e.code}\n{e.read().decode(errors='replace')}")
        if e.code in (401, 403):
            print("::error::La clé API n'a pas le droit de gérer Xcode Cloud "
                  "(rôle Admin, ou App Manager avec accès Xcode Cloud).")
        sys.exit(1)


def summary(wf):
    a = wf["attributes"]
    starts = [k for k, v in a.items() if k.endswith("StartCondition") and v]
    actions = [x.get("actionType") for x in a.get("actions") or []]
    return f"« {a['name']} » activé={a.get('isEnabled')} démarrages={starts} actions={actions}"


def main():
    apps = call("GET", f"/v1/apps?filter[bundleId]={BUNDLE_ID}")["data"]
    if not apps:
        sys.exit(f"::error::Aucune app {BUNDLE_ID} dans App Store Connect.")
    product = call("GET", f"/v1/apps/{apps[0]['id']}/ciProduct")["data"]
    workflows = call("GET", f"/v1/ciProducts/{product['id']}/workflows")["data"]
    print(f"{len(workflows)} workflow(s) Xcode Cloud :")
    for wf in workflows:
        print("  avant :", summary(wf))

    for wf in workflows:
        a = wf["attributes"]
        print("  détail des démarrages :", json.dumps(
            {k: v for k, v in a.items() if k.endswith("StartCondition")}, ensure_ascii=False))
        if not any(x.get("actionType") == "ARCHIVE" for x in a.get("actions") or []):
            continue
        name = a["name"].replace(" Release", "").strip() or "Default"
        body = {"data": {"type": "ciWorkflows", "id": wf["id"], "attributes": {
            "name": name[:100],
            "isEnabled": False,
        }}}
        print("  après :", summary(call("PATCH", f"/v1/ciWorkflows/{wf['id']}", body)["data"]))

    print("Numéro de build Xcode Cloud : l'API ne permet pas de le régler.")


if __name__ == "__main__":
    main()
