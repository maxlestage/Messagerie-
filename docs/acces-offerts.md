# Accès offerts — ouvrir Brocolis Pro sans passer par l'App Store

Pour les comptes de l'auteur et de ses proches. Ce n'est **pas** un moyen de
vendre : vendre une fonction de l'app hors achat intégré est un motif de rejet
par Apple. Offrir un accès à soi-même et à un ami ne l'est pas.

## Par e-mail (recommandé) : « Se connecter avec Apple »

Le serveur lit `BROCOLIS_PRO_EMAILS` : une liste d'e-mails séparés par des
virgules (casse et espaces ignorés).

```sh
heroku config:set \
  BROCOLIS_PRO_EMAILS="toi@icloud.com,ton-ami@exemple.fr" \
  --app brocolis-serveur
```

Sur le tableau de bord Heroku : app → **Settings** → **Reveal Config Vars** →
clé `BROCOLIS_PRO_EMAILS`. Le serveur redémarre tout seul.

Dans l'app : section **Forfait** → **Se connecter avec Apple** → choisir
**Partager mon e-mail** (pas « Masquer » : Apple donnerait alors une adresse
relais, qui ne figure pas dans la liste). L'accès Pro s'ouvre aussitôt.

Comment c'est sûr : l'app envoie au serveur le jeton d'identité signé par Apple
(`POST /v1/plan/apple`). Le serveur vérifie la signature avec les clés
publiques d'Apple, l'émetteur, l'audience (le bundle ID de l'app, ou
`APPLE_BUNDLE_ID` s'il est défini), l'expiration et que l'e-mail est vérifié.
Personne ne peut donc se réclamer d'un e-mail qui n'est pas le sien.

Ce qui est conservé : uniquement si l'e-mail est dans la liste, une ligne
« appareil → e-mail » (table `plan_grants`). Un e-mail hors liste n'est pas
gardé. La liste est relue à chaque appel : retirer un e-mail retire l'accès.
**Déconnecter** dans l'app efface la ligne (`DELETE /v1/plan/apple`).

Prérequis Apple : la capacité **Sign in with Apple** sur l'identifiant
`rs.brocolis.messagerie`. La signature automatique du workflow TestFlight
l'active normalement d'elle-même ; sinon, l'ajouter dans developer.apple.com →
Identifiers. Penser aussi à déclarer « Adresse e-mail — fonctionnalité de
l'app » dans la confidentialité App Store Connect.

## Par identifiant d'appareil


Le serveur lit `BROCOLIS_PRO_IDS` : une liste d'identifiants d'appareil séparés
par des virgules. Tout appareil qui s'y trouve obtient **Brocolis Pro**.

```sh
heroku config:set \
  BROCOLIS_PRO_IDS="TON-IDENTIFIANT,CELUI-DE-TON-AMI" \
  --app brocolis-serveur
```

Les espaces autour des virgules sont tolérés — une liste se colle souvent à la
main. Pour retirer un accès, retire l'identifiant et redéploie ; pour tout
fermer, `heroku config:unset BROCOLIS_PRO_IDS`.

## Où trouver un identifiant d'appareil

Dans l'app : écran principal → section **Cet appareil** → *Copier
l'identifiant*. Demande la même chose à ton ami, depuis son iPhone.

C'est un UUID opaque, déjà envoyé à chaque requête (en-tête `X-User-Id`) pour
que le serveur reconnaisse tes messages. Il ne révèle rien de toi, et le mettre
dans cette liste n'ajoute aucune donnée personnelle côté serveur.

## Comment l'app l'apprend

`GET /v1/plan` renvoie le palier offert à l'appelant :

```json
{ "tier": "pro", "email": "toi@icloud.com" }
```

(`email` vaut `null` si aucun e-mail Apple n'est rattaché à l'appareil.)

L'app interroge cette route au lancement et retient la réponse. Le palier
appliqué est **le plus ouvert** entre l'abonnement App Store et l'accès offert :

| App Store | Serveur | Appliqué |
|---|---|---|
| — | Pro | **Pro** |
| Brocolis+ | — | **Brocolis+** |
| Brocolis+ | Pro | **Pro** |
| Pro | — | **Pro** |

Les deux sources sont rangées séparément dans l'app. C'est volontaire : retirer
un accès offert ne doit jamais emporter un abonnement réellement payé, et un
rafraîchissement StoreKit ne doit jamais effacer un accès offert. Un test
verrouille cette propriété.

Serveur injoignable : l'app **garde la dernière valeur connue**. On ne retire
pas un accès pour une coupure de connexion.

## Ce que ça ne fait pas

Le serveur ne sait **rien** des abonnements App Store — ceux-là, seul l'appareil
les connaît via StoreKit. `/v1/plan` ne parle que des accès offerts.

`BROCOLIS_PRO_IDS` est un filtre par identifiant d'appareil, pas une
authentification : qui connaîtrait un UUID listé pourrait s'en réclamer.
`BROCOLIS_PRO_EMAILS` n'a pas ce défaut (l'e-mail est prouvé par Apple). Dans
les deux cas, c'est fait pour quelques comptes de confiance, pas pour vendre.
