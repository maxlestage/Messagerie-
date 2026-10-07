# Achats intégrés — Brocolis+

Deux offres, un seul contenu débloqué. Tout passe par **StoreKit 2** : Apple
l'exige dès qu'un paiement ouvre une fonction de l'app. Un lien vers Stripe ou
un paiement externe serait un motif de rejet.

## Ce qui est gratuit, et le reste

| | Gratuit | Brocolis+ |
|---|---|---|
| Chiffrement de bout en bout | ✅ illimité | ✅ |
| Lire / **recevoir** photos et vocaux | ✅ | ✅ |
| Extension Partager, clavier, iMessage, widgets, Live Activity, Siri | ✅ | ✅ |
| App Apple Watch | ✅ | ✅ |
| Nombre de clés 🔑 | 3 | illimité |
| **Envoyer** une photo chiffrée | — | ✅ |
| **Envoyer** un message vocal chiffré | — | ✅ |
| Expiration automatique des clés | — | ✅ |

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

| Identifiant | Type | Prix proposé |
|---|---|---|
| `rs.brocolis.messagerie.plus.monthly` | Abonnement auto-renouvelable, 1 mois | 2,99 € |
| `rs.brocolis.messagerie.plus.lifetime` | Non consommable | 49,99 € |

Marche à suivre : App Store Connect → ton app → **Monétisation** →
*Abonnements* (pour le mensuel, dans un groupe d'abonnement nommé p. ex.
« Brocolis+ ») et *Achats intégrés* → *Non consommable* (pour l'offre à vie).
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
StoreKit avec les deux identifiants ci-dessus pour acheter, annuler, rembourser
et faire expirer un abonnement sans compte réel.

En TestFlight, les achats passent par le **bac à sable** : aucun débit réel.

## Où ça vit dans le code

| Rôle | Fichier |
|---|---|
| Ce qui est gratuit, ce qui ne l'est pas (pur, testé) | `Shared/BrocolisPlan.swift` |
| Achat, restauration, état réel d'après l'App Store | `Brocolis/BrocolisStore.swift` |
| Écran des deux offres | `Brocolis/PaywallView.swift` |
| Portes : clés, photo, vocal | `Brocolis/RootView.swift`, `Brocolis/MessagingView.swift` |

`BrocolisStore` est **seul** à écrire `BrocolisPlan.isPlus`, et le recalcule
toujours depuis `Transaction.currentEntitlements` — jamais depuis un drapeau
qu'on aurait posé soi-même. Un remboursement (`revocationDate`) referme donc
l'accès tout seul.
