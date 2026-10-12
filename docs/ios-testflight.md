# Livraison iOS — TestFlight / App Store (CI)

Le workflow [`.github/workflows/ios-testflight.yml`](../.github/workflows/ios-testflight.yml)
compile, **signe** et **téléverse** l'app Brocolis 🥦 sur TestFlight, sur un
runner macOS GitHub Actions. La signature est **automatique (« cloud »)** via une
**clé API App Store Connect** : aucun certificat ni profil à gérer à la main.

## 1. Créer une clé API App Store Connect

1. [App Store Connect](https://appstoreconnect.apple.com/) → **Users and Access**
   → onglet **Integrations** → **App Store Connect API** → **Keys**.
2. **Generate API Key**. Nom libre (ex. « CI TestFlight »), rôle **App Manager**
   (suffisant pour téléverser des builds).
3. Note l'**Issuer ID** (UUID affiché en haut) et le **Key ID** (colonne de la
   clé). **Télécharge le fichier `.p8`** — il n'est **téléchargeable qu'une
   fois**. Garde-le en lieu sûr (ne pas committer).

## 2. Enregistrer les secrets GitHub

Dépôt → **Settings → Secrets and variables → Actions → New repository secret** :

| Secret | Valeur |
|--------|--------|
| `ASC_KEY_ID` | le **Key ID** (ex. `ABC123DEF4`) |
| `ASC_ISSUER_ID` | l'**Issuer ID** (UUID) |
| `ASC_KEY_P8` | **tout le contenu** du fichier `.p8` (avec `-----BEGIN PRIVATE KEY-----` … `-----END PRIVATE KEY-----`, multi-lignes) |

## 3. Prérequis côté App Store Connect (une seule fois)

- L'enregistrement de l'app (bundle ID **`rs.brocolis.messagerie`**) doit exister :
  **Apps → +** → nouvelle app iOS, associée à ce bundle ID (créé automatiquement
  par la signature Xcode ou via **Certificates, IDs & Profiles → Identifiers**).
- Accepter les éventuels contrats en attente (**Agreements, Tax, and Banking**).

## 4. Déclencher une livraison

- **Par tag** (recommandé) : pousser un tag `v*`.
  ```bash
  git tag v1.0.0
  git push origin v1.0.0
  ```
- **Manuellement** : onglet **Actions → iOS TestFlight → Run workflow**.

Le **numéro de build** (`CURRENT_PROJECT_VERSION`) est dérivé du numéro de run CI
(`+10000`), donc monotone et toujours au-dessus des sorties Xcode Cloud (compteur
réglé à 5000, voir [XCODE_CLOUD.md](XCODE_CLOUD.md)). Le **numéro de version** affiché
(`MARKETING_VERSION`, ex. `1.0`) reste géré dans le projet Xcode : incrémente-le
dans Xcode pour une nouvelle version App Store, puis tague.

## 5. Conformité export (chiffrement)

L'app déclare `ITSAppUsesNonExemptEncryption = YES` (AES-256-GCM + X25519). App
Store Connect demandera la **conformité export** au premier build : généralement
un *year-end self-classification report* auprès de la BIS. Cette étape se règle
**côté App Store Connect**, pas dans le projet.

## 6. En cas d'échec de la signature « cloud »

### Cas rencontré : « No profiles for …watchkitapp were found »

```
error: Authentication failed: Make sure a bearer token was provided, it is
properly configured and signed, and it has not expired.
error: No profiles for 'rs.brocolis.messagerie.watchkitapp' were found
(in target 'BrocolisWatch' from project 'Brocolis')
```

L'archive échoue sur la cible **montre**. Les deux messages vont ensemble : la
signature automatique n'a pas pu s'authentifier auprès d'App Store Connect,
elle n'a donc pas pu créer le profil manquant. À vérifier, dans cet ordre :

1. **L'App ID de la montre existe-t-il ?** `rs.brocolis.messagerie.watchkitapp`
   sur developer.apple.com → Certificates, IDs & Profiles → Identifiers, avec
   la capacité **App Groups** activée pour `group.rs.brocolis.messagerie` —
   c'est ce que réclame `BrocolisWatch/BrocolisWatch.entitlements`. L'app montre
   est arrivée après les autres cibles : son identifiant a pu ne jamais être
   enregistré.
2. **La clé API App Store Connect est-elle encore valide ?** Le message
   « Authentication failed / bearer token » pointe vers `ASC_KEY_ID`,
   `ASC_ISSUER_ID` et `ASC_KEY_P8` (secrets GitHub) — une clé révoquée ou un
   `.p8` tronqué au copier-coller donnent exactement cette erreur.

Tant que l'un des deux bloque, l'archive s'arrête avant l'export : rien ne part
sur TestFlight, il n'y a donc pas de build fantôme à retirer.

### Cas général

`-allowProvisioningUpdates` crée normalement le certificat de distribution et le
profil automatiquement. Si le runner CI n'y parvient pas (message de signature),
la parade robuste est [`fastlane match`](https://docs.fastlane.tools/actions/match/) :
certificats/profils stockés chiffrés dans un dépôt privé, récupérés en CI. Dis-le
si tu veux que je bascule le workflow sur `match`.
