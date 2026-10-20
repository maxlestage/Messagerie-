#!/bin/sh
#
#  ci_post_clone.sh
#  Exécuté par Xcode Cloud juste APRÈS le clone du dépôt, avant le build.
#
#  Brocolis 🥦 n'a qu'une dépendance : le paquet SwiftPM BrocolisProto (le
#  protocole v3), dans le dépôt lui-même (Package.swift à la racine). Xcode le
#  résout seul ; Xcode Cloud exige le fichier Package.resolved du projet
#  (Brocolis.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/), committé —
#  il épingle swift-crypto, résolu même s'il ne sert que hors des plateformes
#  Apple. Rien à installer ici. Ce script est laissé comme point d'accroche
#  officiel — si un jour une étape de préparation devient nécessaire
#  (génération de code, secrets, etc.), c'est ici qu'elle va.
#
#  Xcode Cloud détecte ce fichier automatiquement s'il est dans `ci_scripts/`
#  à la racine du dépôt (ou à côté du projet Xcode) ET s'il est exécutable
#  (`chmod +x`).
#

set -e

echo "── ci_post_clone : Brocolis 🥦 ──"

# Deux chaînes, chacune son rôle :
#  - GitHub Actions (ios-testflight.yml) livre TestFlight automatiquement, après
#    les tests iOS, avec des numéros de build 1000+.
#  - Xcode Cloud compile et teste à chaque poussée (actions build/test/analyze),
#    mais n'ARCHIVE pas : Xcode Cloud impose son propre compteur (100, 101…),
#    plus petit que celui de GitHub, et ses envois se mélangeaient aux bons sur
#    TestFlight.
# Xcode Cloud n'archive (envoi TestFlight / App Store) que si on le demande
# explicitement : BROCOLIS_XCODE_CLOUD_UPLOAD=1 dans les variables du workflow.
# (Le workflow est de toute façon désactivé par scripts/xcode_cloud_setup.py.)
if [ "$CI_XCODEBUILD_ACTION" = "archive" ]; then
  if [ "$BROCOLIS_XCODE_CLOUD_UPLOAD" = "1" ]; then
    echo "Archive Xcode Cloud autorisée (workflow « $CI_WORKFLOW », tag « $CI_TAG »)."
  else
    echo "error: TestFlight est livré par GitHub Actions (builds 10000+) — archive Xcode Cloud arrêtée."
    echo "error: Pour livrer depuis Xcode Cloud : BROCOLIS_XCODE_CLOUD_UPLOAD=1 dans les variables du workflow."
    exit 1
  fi
fi

echo "Rien à installer (BrocolisProto est dans le dépôt)."
echo "Xcode : $(xcodebuild -version 2>/dev/null | tr '\n' ' ' || echo 'indisponible')"

exit 0
