# Achats intégrés — Brocolis+ et Brocolis Pro

Deux **abonnements mensuels**, sans engagement. Ni offre annuelle, ni achat à
vie. Tout passe par **StoreKit 2** : Apple l'exige dès qu'un paiement ouvre une
fonction de l'app. Un lien vers Stripe ou un paiement externe serait un motif
de rejet.

Le découpage suit la dépense : Brocolis+ ouvre ce qui ne coûte presque rien à
servir (des clés, un minuteur), Brocolis Pro ouvre les médias — le stockage et
la bande passante que le serveur paie vraiment.

## Ce qui est gratuit, et le reste

| | Gratuit | Brocolis+ | Brocolis Pro |
|---|---|---|---|
| Chiffrement de bout en bout | ✅ illimité | ✅ | ✅ |
| Lire / **recevoir** photos et vocaux | ✅ | ✅ | ✅ |
| Partager, clavier, iMessage, widgets, Live Activity, Siri | ✅ | ✅ | ✅ |
| App Apple Watch | ✅ | ✅ | ✅ |
| Nombre de clés 🔑 | 3 | illimité | illimité |
| Expiration automatique des clés | — | ✅ | ✅ |
| **Envoyer** une photo chiffrée | — | — | ✅ |
| **Envoyer** un message vocal chiffré | — | — | ✅ |

Trois règles sont figées dans le code et verrouillées par `BrocolisPlanTests` :

1. **Le chiffrement ne se vend pas.** C'est la promesse du produit.
2. **Recevoir est toujours gratuit.** Seul l'envoi de médias passe une porte —
   sinon un abonné enverrait une photo qu'un non-abonné ne pourrait pas ouvrir.
3. **Aucune clé existante n'est jamais retirée.** La limite ne s'applique qu'à
   l'ajout : qui a déjà dix clés les garde toutes.

## Les deux produits à créer dans App Store Connect

Les identifiants doivent correspondre **exactement** à
`Shared/BrocolisPlan.swift`, sinon StoreKit ne renvoie rien et l'écran d'offres
reste vide.

| Identifiant | Type | Niveau | Prix proposé |
|---|---|---|---|
| `rs.brocolis.messagerie.plus.monthly` | Abonnement auto-renouvelable, 1 mois | 2 | 2,99 €/mois |
| `rs.brocolis.messagerie.pro.monthly` | Abonnement auto-renouvelable, 1 mois | 1 | 6,99 €/mois |

Marche à suivre : App Store Connect → ton app → **Monétisation** →
*Abonnements*. Crée **un seul groupe d'abonnement** (p. ex. « Brocolis ») et
mets les deux produits dedans.

Le groupe unique n'est pas un détail : c'est ce qui permet de passer de l'un à
l'autre sans payer deux fois, Apple gérant le prorata. Dans le groupe, le
**niveau** ordonne les formules — niveau 1 pour la plus complète (Pro),
niveau 2 pour Brocolis+ — pour qu'Apple traite le passage à Pro comme une
montée en gamme, immédiate, et le retour vers + comme une descente, à la fin
de la période en cours.

Chaque produit a besoin d'un nom affiché, d'une description, d'une capture
d'écran de validation, et doit être soumis avec une version de l'app.

Tant que les produits ne sont pas **approuvés**, `Product.products(for:)` ne
renvoie rien : l'écran affiche « Offres indisponibles », et l'app continue de
fonctionner normalement. C'est voulu — un échec de StoreKit ne doit jamais
empêcher de chiffrer.

## Ce qu'Apple vérifie sur l'écran d'offres

`PaywallView` les couvre déjà, mais un oubli lors d'une refonte vaut un rejet :

- le nom de l'offre et **sa durée** (« renouvelé tous les 1 mois ») ;
- le **prix**, pris de `product.displayPrice` (localisé par l'App Store) ;
- un bouton **Restaurer les achats** ;
- des liens vers les **conditions d'utilisation** et la **politique de
  confidentialité** ;
- la mention du renouvellement automatique et de la résiliation.

## Tester sans payer

En local, Xcode sait simuler l'App Store : *Product → Scheme → Edit Scheme →
Run → Options → StoreKit Configuration*. Crée un fichier de configuration
StoreKit avec les deux identifiants ci-dessus, dans un même groupe, pour
acheter, changer de formule, annuler, rembourser et faire expirer un abonnement
sans compte réel.

En TestFlight, les achats passent par le **bac à sable** : aucun débit réel.

## Où ça vit dans le code

| Rôle | Fichier |
|---|---|
| Les paliers, ce que chacun ouvre (pur, testé) | `Shared/BrocolisPlan.swift` |
| Achat, restauration, état réel d'après l'App Store | `Brocolis/BrocolisStore.swift` |
| Écran des deux offres | `Brocolis/PaywallView.swift` |
| Portes : clés, expiration, photo, vocal | `Brocolis/RootView.swift`, `Brocolis/MessagingView.swift` |

`BrocolisStore` est **seul** à écrire `BrocolisPlan.tier`, et le recalcule
toujours depuis `Transaction.currentEntitlements` — jamais depuis un drapeau
qu'on aurait posé soi-même. Un remboursement (`revocationDate`) referme donc
l'accès tout seul. Si les deux abonnements se chevauchent le temps d'un
changement de formule, le plus ouvert l'emporte : on ne retire jamais à
quelqu'un ce qu'il vient de payer.
