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

# Deux chaînes, chacune son rôle :
#  - GitHub Actions (ios-testflight.yml) livre TestFlight automatiquement, après
#    les tests iOS, avec des numéros de build 1000+.
#  - Xcode Cloud compile et teste à chaque poussée (actions build/test/analyze),
#    mais n'ARCHIVE pas : Xcode Cloud impose son propre compteur (100, 101…),
#    plus petit que celui de GitHub, et ses envois se mélangeaient aux bons sur
#    TestFlight.
# Xcode Cloud archive quand même (envoi TestFlight / App Store) si :
#  - le build part d'un tag (CI_TAG, ex. v1.0.5) ;
#  - ou le nom du workflow contient « Release » ou « App Store » ;
#  - ou BROCOLIS_XCODE_CLOUD_UPLOAD=1 dans les variables du workflow.
if [ "$CI_XCODEBUILD_ACTION" = "archive" ]; then
  case "$CI_WORKFLOW" in
    *Release*|*release*|*"App Store"*|*"app store"*) release=1 ;;
    *) release=0 ;;
  esac
  if [ -n "$CI_TAG" ] || [ "$release" = 1 ] || [ "$BROCOLIS_XCODE_CLOUD_UPLOAD" = "1" ]; then
    echo "Archive Xcode Cloud autorisée (workflow « $CI_WORKFLOW », tag « $CI_TAG »)."
  else
    echo "error: TestFlight est livré par GitHub Actions (builds 10000+) — archive Xcode Cloud arrêtée."
    echo "error: Pour ce workflow, remplace l'action Archive par Test (ou nomme-le « Release » pour livrer)."
    exit 1
  fi
fi

echo "Aucune dépendance externe à installer."
echo "Xcode : $(xcodebuild -version 2>/dev/null | tr '\n' ' ' || echo 'indisponible')"

exit 0
