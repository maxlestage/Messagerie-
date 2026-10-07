# Accès offerts — ouvrir Brocolis Pro sans passer par l'App Store

Pour les comptes de l'auteur et de ses proches. Ce n'est **pas** un moyen de
vendre : vendre une fonction de l'app hors achat intégré est un motif de rejet
par Apple. Offrir un accès à soi-même et à un ami ne l'est pas.

## En une variable d'environnement

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
{ "tier": "pro" }
```

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

La liste est un filtre par identifiant d'appareil, pas une authentification :
qui connaîtrait un UUID listé pourrait s'en réclamer. Acceptable pour deux
comptes de confiance ; à ne pas transformer en système d'abonnement.
