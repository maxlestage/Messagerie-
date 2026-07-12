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
echo "Aucune dépendance externe à installer."
echo "Xcode : $(xcodebuild -version 2>/dev/null | tr '\n' ' ' || echo 'indisponible')"

exit 0
