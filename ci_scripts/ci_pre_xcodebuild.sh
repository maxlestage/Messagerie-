#!/bin/sh
#
#  ci_pre_xcodebuild.sh
#  Exécuté par Xcode Cloud juste AVANT chaque build (après ci_post_clone).
#
#  Rôle : donner à l'archive un numéro de build (CFBundleVersion) UNIQUE et
#  MONOTONE, tiré de `CI_BUILD_NUMBER` fourni par Xcode Cloud.
#
#  Pourquoi c'est indispensable :
#    Le projet fige `CURRENT_PROJECT_VERSION = 1`. Sans ce script, chaque run
#    archive donc toujours « 1.0 (1) ». App Store Connect exige un numéro de
#    build strictement croissant : au 2ᵉ upload il voit un DOUBLON, traite le
#    build (« Processing ») puis le RETIRE (mail ITMS-90xxx « redundant binary /
#    bundle version must be higher »). Résultat : TestFlight garde l'ancien
#    build et « rien ne s'actualise ».
#
#  Xcode Cloud détecte ce fichier automatiquement s'il est dans `ci_scripts/`
#  à la racine du dépôt ET s'il est exécutable (`chmod +x`).
#
set -e

if [ -z "$CI_BUILD_NUMBER" ]; then
  echo "ci_pre_xcodebuild : CI_BUILD_NUMBER absent (build local ?) — numéro du projet conservé."
  exit 0
fi

# (Inactif tant que ci_post_clone.sh arrête les archives Xcode Cloud.)
# On décale de +1000 pour rester au-dessus des anciens uploads faits par le
# workflow GitHub Actions (qui utilisait github.run_number + 1000). Garde les
# deux chemins de livraison sans collision de numéros.
BUILD_NUMBER=$(( CI_BUILD_NUMBER + 1000 ))

echo "── ci_pre_xcodebuild : Brocolis 🥦 ──"
echo "CI_BUILD_NUMBER=$CI_BUILD_NUMBER → CURRENT_PROJECT_VERSION=$BUILD_NUMBER"

# Le numéro de build est un réglage de projet (CURRENT_PROJECT_VERSION), pas une
# clé d'Info.plist (GENERATE_INFOPLIST_FILE l'injecte au build). On le réécrit
# donc directement dans le pbxproj, pour TOUTES les cibles à la fois.
PBXPROJ="$CI_PRIMARY_REPOSITORY_PATH/Brocolis.xcodeproj/project.pbxproj"

if [ ! -f "$PBXPROJ" ]; then
  echo "::error::pbxproj introuvable ($PBXPROJ)"
  exit 1
fi

# Écriture via fichier temporaire (portable BSD/macOS *et* GNU, contrairement à
# `sed -i` dont la syntaxe diffère entre les deux).
TMP="${PBXPROJ}.tmp"
sed -E "s/CURRENT_PROJECT_VERSION = [0-9]+;/CURRENT_PROJECT_VERSION = ${BUILD_NUMBER};/g" "$PBXPROJ" > "$TMP"
mv "$TMP" "$PBXPROJ"

echo "Numéros de build après réécriture :"
grep -c "CURRENT_PROJECT_VERSION = ${BUILD_NUMBER};" "$PBXPROJ" | sed 's/^/  occurrences mises à jour : /'

exit 0
