# Mises à jour push — Live Activity « Brocolis actif »

Ce qui a été activé côté app pour piloter la Live Activity 🥦 **à distance** (et,
plus largement, recevoir des notifications push) :

| Élément | Fichier |
|--------|---------|
| Entitlement `aps-environment` (APNs) | `Brocolis/Brocolis.entitlements` |
| Enregistrement APNs au lancement + capture du device token | `Brocolis/BrocolisApp.swift` (`AppDelegate`) |
| Live Activity demandée avec `pushType: .token` + capture du push token | `Brocolis/BrocolisLiveActivity.swift` |
| Mises à jour fréquentes autorisées | `INFOPLIST_KEY_NSSupportsLiveActivitiesFrequentUpdates` |

## Où atterrissent les tokens

Rangés dans l'App Group `group.rs.brocolis.messagerie` (UserDefaults) :

| Clé | Contenu |
|-----|---------|
| `live_activity_push_token` | push token (hex) de la Live Activity en cours — **la cible des updates** |
| `apns_device_token` | device token APNs de l'app (push classiques) |

Un serveur récupère le `live_activity_push_token` (via ton canal : rendez-vous,
API dédiée…) puis pousse les mises à jour.

## Envoyer une mise à jour (APNs)

Prérequis : une **clé d'authentification APNs** (`.p8`) — developer.apple.com →
**Keys** → *Apple Push Notifications service (APNs)* (distincte de la clé App
Store Connect de la CI). Génère un JWT `ES256` (issuer = Team ID `2FW8T4UX4L`,
`kid` = Key ID) pour l'en-tête `authorization`.

```
POST https://api.sandbox.push.apple.com/3/device/<live_activity_push_token>
     (production : https://api.push.apple.com/3/device/<token>)

authorization: bearer <JWT ES256>
apns-topic: rs.brocolis.messagerie.push-type.liveactivity
apns-push-type: liveactivity
apns-priority: 10
```

Corps — **mise à jour** :

```json
{
  "aps": {
    "timestamp": 1735732800,
    "event": "update",
    "content-state": { "since": 1735732800 }
  }
}
```

Corps — **fin** de l'activité :

```json
{
  "aps": {
    "timestamp": 1735732800,
    "event": "end",
    "dismissal-date": 1735732800,
    "content-state": { "since": 1735732800 }
  }
}
```

> `content-state` doit correspondre à `BrocolisActivityAttributes.ContentState`
> (ici `{ "since": … }`). Sandbox pour les builds `development`, production pour
> TestFlight/App Store.

## Ce qui reste à faire

Le **client** est prêt (tokens capturés, activité pilotable par push). Il manque
le **serveur d'envoi** : stocker `live_activity_push_token` et émettre les
requêtes APNs ci-dessus. Il pourrait être greffé sur le serveur de rendez-vous
existant (Heroku). Dis-le si tu veux que je l'ajoute.
