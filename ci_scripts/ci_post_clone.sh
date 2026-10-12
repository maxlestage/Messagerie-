#!/bin/sh
#
#  ci_post_clone.sh
#  Exécuté par Xcode Cloud juste APRÈS le clone du dépôt, avant le build.
#
#  Brocolis 🥦 n'a AUCUNE dépendance externe (pas de CocoaPods, pas de Carthage,
#  pas de package SPM tiers) : il n'y a donc rien à installer ici. Ce script est
#  laissé comme point d'accroche officiel — si un jour une étape de préparation
#  devient nécessaire (génération de code, secrets, etc.), c'est ici qu'elle va.
#
#  Xcode Cloud détecte ce fichier automatiquement s'il est dans `ci_scripts/`
#  à la racine du dépôt (ou à côté du projet Xcode) ET s'il est exécutable
#  (`chmod +x`).
#

set -e

echo "── ci_post_clone : Brocolis 🥦 ──"

# Une seule chaîne livre sur TestFlight : GitHub Actions (ios-testflight.yml),
# après les tests iOS, avec des numéros de build 1000+. Xcode Cloud, lui,
# impose son propre compteur (100, 101…) quoi que dise ci_pre_xcodebuild.sh :
# ses builds arrivaient sur TestFlight avec des numéros PLUS PETITS que ceux
# de GitHub et se mélangeaient aux bons. On arrête donc ici toute archive
# Xcode Cloud (= tout envoi TestFlight). Les builds/tests Xcode Cloud sans
# archive continuent. Pour lui rendre la main : variable d'environnement
# BROCOLIS_XCODE_CLOUD_UPLOAD=1 dans le workflow Xcode Cloud.
if [ "$CI_XCODEBUILD_ACTION" = "archive" ] && [ "$BROCOLIS_XCODE_CLOUD_UPLOAD" != "1" ]; then
  echo "error: Livraison TestFlight faite par GitHub Actions (builds 1000+) — archive Xcode Cloud arrêtée."
  echo "error: Désactive ce workflow dans App Store Connect → Xcode Cloud pour ne plus recevoir cet échec."
  exit 1
fi

echo "Aucune dépendance externe à installer."
echo "Xcode : $(xcodebuild -version 2>/dev/null | tr '\n' ' ' || echo 'indisponible')"

exit 0
