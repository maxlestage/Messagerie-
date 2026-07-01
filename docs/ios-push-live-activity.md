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

## Serveur d'envoi (intégré au rendez-vous)

Le serveur de rendez-vous (`server/`) sait maintenant relayer ces pushs, via un
client APNs sans dépendance (`server/apns.js`, JWT ES256 + HTTP/2). Configure les
variables `APNS_*` (voir `server/.env.example`) — sinon `/update` répond `503`.

Deux endpoints :

```
POST /push/live-activity/token   { code, peerId, token }
     → l'app enregistre le push token de sa Live Activity.

POST /push/live-activity/update  { code, peerId, event, contentState[, dismissalDate] }
     → le serveur envoie le push APNs (update / end) au token enregistré.
       404 si aucun token, 503 si APNS_* non configuré.
```

### Côté app (déjà branché)

- **Enregistrement du token** : après un appairage (à deux / groupe), l'app
  poste son push token sur `/push/live-activity/token` sous `(code, peerId)`
  (`BrocolisPush.registerLiveActivityToken`).
- **Déclencheur** : le bouton **« Notifier mes correspondants »** (écran
  principal, section Correspondant) appelle `/push/live-activity/update` pour
  chaque pair appairé (`BrocolisPush.notifyPeers`). Un pair dont la Live
  Activity n'est pas active, ou si `APNS_*` n'est pas configuré, est ignoré.

Le `contentState` envoyé est `{ "since": <unix> }` ; ajuste-le si tu enrichis
`BrocolisActivityAttributes.ContentState`.
