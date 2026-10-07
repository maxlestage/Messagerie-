//! Dictionnaire FR / EN / ES. Une table par langue : la même clé doit exister
//! dans les trois (vérifié par les tests en bas du fichier).

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Fr,
    En,
    Es,
}

impl Lang {
    pub const ALL: [Lang; 3] = [Lang::Fr, Lang::En, Lang::Es];

    pub fn code(self) -> &'static str {
        match self {
            Lang::Fr => "fr",
            Lang::En => "en",
            Lang::Es => "es",
        }
    }

    pub fn from_code(code: &str) -> Option<Lang> {
        let code = code.to_ascii_lowercase();
        Lang::ALL.into_iter().find(|l| code.starts_with(l.code()))
    }

    fn table(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Lang::Fr => FR,
            Lang::En => EN,
            Lang::Es => ES,
        }
    }

    /// Texte traduit ; retombe sur le français, puis sur la clé elle-même.
    pub fn t(self, key: &str) -> &'static str {
        lookup(self.table(), key)
            .or_else(|| lookup(FR, key))
            .unwrap_or_else(|| {
                gloo::console::warn!("clé i18n manquante", key.to_string());
                "…"
            })
    }
}

fn lookup(table: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

#[cfg(test)]
const BROCOLIS_LINK: &str = r#"<a href="https://maxlestage.github.io/brocolis/" target="_blank" rel="noopener noreferrer">brocolis</a>"#;

macro_rules! tagline {
    ($pre:literal, $post:literal) => {
        concat!(
            $pre,
            r#"<a href="https://maxlestage.github.io/brocolis/" target="_blank" rel="noopener noreferrer">brocolis</a>"#,
            $post
        )
    };
}

#[rustfmt::skip]
const FR: &[(&str, &str)] = &[
    ("meta.title", "Brocolis 🥦 messageries — chiffrement sélectif"),
    ("meta.desc", "Brocolis messageries : ajoute le chiffrement sélectif de brocolis à tes apps de messagerie iOS via une extension de partage. Appairage X25519, clé de groupe, expiration."),
    ("meta.ogTitle", "Brocolis 🥦 messageries"),
    ("meta.ogDesc", "Chiffrement sélectif pour tes messageries, bâti sur brocolis."),
    ("hero.alt", "Brocolis messageries"),
    ("hero.badge", "iPhone · Apple Watch · Live Activity"),
    ("hero.title", "Tes messageries,"),
    ("hero.titleAccent", "chiffrées à la carte."),
    ("hero.tagline", tagline!("Chiffrement sélectif pour tes messageries — bâti sur ", ".")),
    ("cta.repo", "Voir le dépôt"),
    ("cta.brocolis", "Projet brocolis"),
    ("cta.server", "Serveur 🛰️"),
    ("cta.salon", "Salon des rendez-vous 🤝"),
    ("cta.pricing", "Voir les formules"),
    ("nav.features", "Fonctionnalités"),
    ("nav.pricing", "Formules"),
    ("nav.doc", "Documentation"),
    ("nav.github", "GitHub"),
    ("nav.brocolis", "brocolis"),
    ("nav.menu", "Menu"),
    ("nav.license", "Licence"),
    ("nav.server", "Serveur"),
    ("nav.salon", "Salon"),
    ("switch.lang", "Langue"),
    ("switch.theme", "Thème"),
    ("theme.green", "Vert"),
    ("theme.light", "Clair"),
    ("theme.dark", "Sombre"),
    ("stat.cipher", "AES-256-GCM"),
    ("stat.cipher.d", "par jeton"),
    ("stat.kex", "X25519"),
    ("stat.kex.d", "appairage"),
    ("stat.server", "0 octet"),
    ("stat.server.d", "en clair côté serveur"),
    ("features.title", "Tout ce qu'il faut, rien de plus"),
    ("features.note", "Brocolis se glisse dans les apps que tu utilises déjà et ne chiffre que ce que tu choisis."),
    ("feat.graft.t", "Se greffe sur tes apps"),
    ("feat.graft.d", "Extension de partage iOS : sélectionne du texte dans WhatsApp, iMessage, Notes… → Partager → Brocolis 🥦."),
    ("feat.crypto.t", "Chiffrement sélectif"),
    ("feat.crypto.d", "Seuls les ((secrets)) deviennent des jetons [[BROCOLIS:v1:…]] (AES-256-GCM). Le service distant ne voit que du chiffré."),
    ("feat.pair.t", "Appairage automatique"),
    ("feat.pair.d", "Échange de clés X25519 via un code court : chaque appareil obtient la clé de l’autre, sans copier-coller."),
    ("feat.group.t", "Clé de groupe"),
    ("feat.group.d", "Un fondateur génère une clé de groupe et la distribue chiffrée à chaque membre (key-wrapping X25519)."),
    ("feat.rotate.t", "Rotation & expiration"),
    ("feat.rotate.d", "Validité configurable, purge automatique à l’ouverture, préavis par notification et action « Prolonger »."),
    ("feat.watch.t", "Apple Watch & Live Activity"),
    ("feat.watch.d", "Suis tes conversations depuis ta montre et sur l’écran verrouillé, toujours déchiffrées sur tes appareils."),
    ("feat.interop.t", "Compatible brocolis"),
    ("feat.interop.d", "Même format de jeton que le proxy Rust brocolis : interopérable des deux côtés."),
    ("pricing.title", "Formules"),
    ("pricing.note", "Abonnements mensuels, sans engagement : tu changes ou résilies quand tu veux depuis l’app (Réglages → Forfait)."),
    ("pricing.month", "/mois"),
    ("pricing.popular", "Le plus complet"),
    ("pricing.foot", "Recevoir une photo ou une note vocale reste toujours gratuit."),
    ("plan.free.name", "Gratuit"),
    ("plan.free.price", "0 €"),
    ("plan.free.f1", "Jusqu’à 3 clés de conversation"),
    ("plan.free.f2", "Messages texte chiffrés"),
    ("plan.free.f3", "Appairage, clé de groupe, montre"),
    ("plan.plus.name", "Brocolis+"),
    ("plan.plus.price", "2,99 €"),
    ("plan.plus.f1", "Clés illimitées"),
    ("plan.plus.f2", "Durée de validité des clés au choix"),
    ("plan.plus.f3", "Tout ce qu’offre la formule gratuite"),
    ("plan.pro.name", "Brocolis Pro"),
    ("plan.pro.price", "6,99 €"),
    ("plan.pro.f1", "Envoi de photos chiffrées"),
    ("plan.pro.f2", "Envoi de notes vocales chiffrées"),
    ("plan.pro.f3", "Tout ce qu’offre Brocolis+"),
    ("doc.title", "Documentation"),
    ("doc.note", "Le README du dépôt (en français)."),
    ("doc.loading", "Chargement du README…"),
    ("doc.unavailable", "README indisponible — voir le dépôt."),
    ("server.title", "Serveur de rendez-vous"),
    ("server.note", "L'espace dédié qui héberge l'API d'appairage… et cette vitrine."),
    ("server.status", "État"),
    ("server.checking", "Vérification…"),
    ("server.online", "En ligne"),
    ("server.offline", "Hors ligne"),
    ("server.latency", "réponse en"),
    ("server.address", "Adresse"),
    ("server.open", "Ouvrir le serveur"),
    ("server.recheck", "Re-vérifier"),
    ("server.api", "Points d'accès"),
    ("server.api.pair", "échange des clés publiques (appairage)"),
    ("server.api.wrap", "distribution de la clé de groupe (chiffrée)"),
    ("server.api.health", "état du service"),
    ("server.privacy", "Le serveur ne voit que des clés publiques et des blobs chiffrés, jamais la clé secrète ni les messages."),
    ("back", "← Retour à l'accueil"),
    ("salon.title", "Salon des rendez-vous"),
    ("salon.intro", "Le salon, c'est l'endroit où deux (ou plusieurs) appareils s'échangent leurs clés publiques pour dériver une même clé secrète — sans jamais l'envoyer. Le serveur ne relaie que du public ; le secret ne quitte jamais les téléphones."),
    ("salon.howTitle", "Comment ça marche"),
    ("salon.step1", "Un appareil crée un code court et affiche son QR / son code."),
    ("salon.step2", "L'autre saisit le même code : chacun publie sa clé publique X25519 dans le salon."),
    ("salon.step3", "Chaque appareil récupère la clé publique de l'autre et dérive la MÊME clé secrète (Diffie-Hellman)."),
    ("salon.step4", "Brocolis s'active tout seul : les messages passent chiffrés avec cette clé."),
    ("salon.fingerprint", "Comparez de vive voix l'empreinte de sécurité affichée des deux côtés : si elle est identique, personne n'a intercepté l'échange (anti-MITM)."),
    ("salon.roomTitle", "Voir un salon en direct"),
    ("salon.roomNote", "Entre un code pour voir qui y est présent (clés publiques seulement). L'appairage réel, lui, se fait dans l'app."),
    ("salon.codeLabel", "Code du salon"),
    ("salon.codePlaceholder", "ex. 4813"),
    ("salon.view", "Voir le salon"),
    ("salon.refreshing", "actualisation…"),
    ("salon.peers", "Participants"),
    ("salon.empty", "Personne dans ce salon pour l'instant."),
    ("salon.pub", "clé publique"),
    ("salon.errorTitle", "Salon injoignable"),
    ("salon.errorCors", "Le serveur n'est pas joignable depuis ce navigateur (souvent : CORS quand la page n'est pas servie par le serveur lui-même). Réessaie depuis le site hébergé par le serveur, ou vérifie qu'il tourne."),
    ("salon.privacy", "Le serveur ne voit que des clés publiques et des jetons chiffrés. Aucune clé secrète, aucun message en clair."),
    ("license.title", "Licence"),
    ("license.note", "Texte de la licence :"),
    ("license.viewFile", "Voir le fichier LICENSE complet →"),
    ("license.full", "Copyright © 2026 LESTAGE Maxime Nathan. Tous droits réservés.

Licence propriétaire — All rights reserved.

Ce logiciel (« Brocolis 🥦 », l'application iOS, son extension, le serveur de
rendez-vous et le site) ainsi que son code source sont la propriété exclusive de
LESTAGE Maxime Nathan. Ils ne peuvent être copiés, modifiés, distribués, publiés
ni utilisés, en tout ou partie, sans autorisation écrite préalable de l'auteur.

Aucun droit, licence ou titre n'est concédé sur le code source. Toute copie,
modification, distribution ou utilisation en violation de la présente licence
est strictement interdite et passible de poursuites.

Ce logiciel accompagne le projet brocolis
(https://github.com/maxlestage/brocolis), également propriété exclusive de
LESTAGE Maxime Nathan ; ses termes de licence propriétaire s'appliquent
également.

LE LOGICIEL EST FOURNI « TEL QUEL », SANS AUCUNE GARANTIE, EXPLICITE OU
IMPLICITE, Y COMPRIS, SANS S'Y LIMITER, LES GARANTIES IMPLICITES DE QUALITÉ
MARCHANDE ET D'ADÉQUATION À UN USAGE PARTICULIER. EN AUCUN CAS L'AUTEUR NE
POURRA ÊTRE TENU RESPONSABLE D'UN QUELCONQUE DOMMAGE, DIRECT OU INDIRECT,
DÉCOULANT DE L'UTILISATION OU DE L'IMPOSSIBILITÉ D'UTILISER CE LOGICIEL.
UTILISATION À VOS PROPRES RISQUES."),
    ("footer.tagline", "Brocolis messageries 🥦 — chiffrement sélectif pour tes messageries. Le contenu de cette page reflète le README du dépôt."),
    ("footer.stack", "Site écrit en Rust 🦀 et compilé en WebAssembly avec Yew."),
    ("footer.credit", "Conçu et développé par Maxime Nathan Lestage"),
];

#[rustfmt::skip]
const EN: &[(&str, &str)] = &[
    ("meta.title", "Brocolis 🥦 messaging — selective encryption"),
    ("meta.desc", "Brocolis messaging: adds brocolis selective encryption to your iOS messaging apps via a share extension. X25519 pairing, group key, expiry."),
    ("meta.ogTitle", "Brocolis 🥦 messaging"),
    ("meta.ogDesc", "Selective encryption for your messaging apps, built on brocolis."),
    ("hero.alt", "Brocolis messaging"),
    ("hero.badge", "iPhone · Apple Watch · Live Activity"),
    ("hero.title", "Your messaging apps,"),
    ("hero.titleAccent", "encrypted your way."),
    ("hero.tagline", tagline!("Selective encryption for your messaging apps — built on ", ".")),
    ("cta.repo", "View the repo"),
    ("cta.brocolis", "brocolis project"),
    ("cta.server", "Server 🛰️"),
    ("cta.salon", "Pairing room 🤝"),
    ("cta.pricing", "See the plans"),
    ("nav.features", "Features"),
    ("nav.pricing", "Plans"),
    ("nav.doc", "Documentation"),
    ("nav.github", "GitHub"),
    ("nav.brocolis", "brocolis"),
    ("nav.menu", "Menu"),
    ("nav.license", "License"),
    ("nav.server", "Server"),
    ("nav.salon", "Room"),
    ("switch.lang", "Language"),
    ("switch.theme", "Theme"),
    ("theme.green", "Green"),
    ("theme.light", "Light"),
    ("theme.dark", "Dark"),
    ("stat.cipher", "AES-256-GCM"),
    ("stat.cipher.d", "per token"),
    ("stat.kex", "X25519"),
    ("stat.kex.d", "pairing"),
    ("stat.server", "0 bytes"),
    ("stat.server.d", "of plaintext on the server"),
    ("features.title", "Everything you need, nothing more"),
    ("features.note", "Brocolis slips into the apps you already use and only encrypts what you choose."),
    ("feat.graft.t", "Hooks into your apps"),
    ("feat.graft.d", "iOS share extension: select text in WhatsApp, iMessage, Notes… → Share → Brocolis 🥦."),
    ("feat.crypto.t", "Selective encryption"),
    ("feat.crypto.d", "Only ((secrets)) become [[BROCOLIS:v1:…]] tokens (AES-256-GCM). The remote service only ever sees ciphertext."),
    ("feat.pair.t", "Automatic pairing"),
    ("feat.pair.d", "X25519 key exchange via a short code: each device gets the other's key, no copy-paste."),
    ("feat.group.t", "Group key"),
    ("feat.group.d", "A founder generates a group key and distributes it encrypted to each member (X25519 key-wrapping)."),
    ("feat.rotate.t", "Rotation & expiry"),
    ("feat.rotate.d", "Configurable validity, auto-purge on launch, an expiry notice and a “Renew” action."),
    ("feat.watch.t", "Apple Watch & Live Activity"),
    ("feat.watch.d", "Follow your conversations from your wrist and on the Lock Screen, always decrypted on your own devices."),
    ("feat.interop.t", "Brocolis-compatible"),
    ("feat.interop.d", "Same token format as the Rust brocolis proxy: interoperable both ways."),
    ("pricing.title", "Plans"),
    ("pricing.note", "Monthly subscriptions, no commitment: switch or cancel any time from the app (Settings → Plan)."),
    ("pricing.month", "/month"),
    ("pricing.popular", "Most complete"),
    ("pricing.foot", "Receiving a photo or a voice note is always free."),
    ("plan.free.name", "Free"),
    ("plan.free.price", "€0"),
    ("plan.free.f1", "Up to 3 conversation keys"),
    ("plan.free.f2", "Encrypted text messages"),
    ("plan.free.f3", "Pairing, group key, watch"),
    ("plan.plus.name", "Brocolis+"),
    ("plan.plus.price", "€2.99"),
    ("plan.plus.f1", "Unlimited keys"),
    ("plan.plus.f2", "Choose how long keys stay valid"),
    ("plan.plus.f3", "Everything in Free"),
    ("plan.pro.name", "Brocolis Pro"),
    ("plan.pro.price", "€6.99"),
    ("plan.pro.f1", "Send encrypted photos"),
    ("plan.pro.f2", "Send encrypted voice notes"),
    ("plan.pro.f3", "Everything in Brocolis+"),
    ("doc.title", "Documentation"),
    ("doc.note", "The repository README (in French)."),
    ("doc.loading", "Loading README…"),
    ("doc.unavailable", "README unavailable — see the repository."),
    ("server.title", "Rendezvous server"),
    ("server.note", "The dedicated space hosting the pairing API… and this very site."),
    ("server.status", "Status"),
    ("server.checking", "Checking…"),
    ("server.online", "Online"),
    ("server.offline", "Offline"),
    ("server.latency", "answered in"),
    ("server.address", "Address"),
    ("server.open", "Open the server"),
    ("server.recheck", "Check again"),
    ("server.api", "Endpoints"),
    ("server.api.pair", "public-key exchange (pairing)"),
    ("server.api.wrap", "group-key distribution (encrypted)"),
    ("server.api.health", "service health"),
    ("server.privacy", "The server only ever sees public keys and encrypted blobs — never the secret key or your messages."),
    ("back", "← Back to home"),
    ("salon.title", "Pairing room"),
    ("salon.intro", "The room is where two (or more) devices swap public keys to derive one shared secret key — without ever sending it. The server only relays public data; the secret never leaves the phones."),
    ("salon.howTitle", "How it works"),
    ("salon.step1", "One device creates a short code and shows its QR / code."),
    ("salon.step2", "The other enters the same code: each publishes its X25519 public key in the room."),
    ("salon.step3", "Each device fetches the other's public key and derives the SAME secret key (Diffie-Hellman)."),
    ("salon.step4", "Brocolis turns on by itself: messages travel encrypted with that key."),
    ("salon.fingerprint", "Compare out loud the security fingerprint shown on both sides: if it matches, nobody intercepted the exchange (anti-MITM)."),
    ("salon.roomTitle", "Watch a room live"),
    ("salon.roomNote", "Enter a code to see who is present (public keys only). The real pairing happens in the app."),
    ("salon.codeLabel", "Room code"),
    ("salon.codePlaceholder", "e.g. 4813"),
    ("salon.view", "View room"),
    ("salon.refreshing", "refreshing…"),
    ("salon.peers", "Participants"),
    ("salon.empty", "Nobody in this room yet."),
    ("salon.pub", "public key"),
    ("salon.errorTitle", "Room unreachable"),
    ("salon.errorCors", "The server isn't reachable from this browser (often CORS when the page isn't served by the server itself). Try from the site hosted by the server, or check it's running."),
    ("salon.privacy", "The server only sees public keys and encrypted tokens. No secret key, no plaintext message."),
    ("license.title", "License"),
    ("license.note", "License text:"),
    ("license.viewFile", "View the full LICENSE file →"),
    ("license.full", "Copyright © 2026 LESTAGE Maxime Nathan. All rights reserved.

Proprietary license — All rights reserved.

This software (“Brocolis 🥦”, the iOS app, its extension, the rendezvous server
and the website) and its source code are the exclusive property of LESTAGE
Maxime Nathan. They may not be copied, modified, distributed, published or used,
in whole or in part, without the author's prior written permission.

No right, license or title is granted over the source code. Any copy,
modification, distribution or use in violation of this license is strictly
prohibited and liable to prosecution.

This software accompanies the brocolis project
(https://github.com/maxlestage/brocolis), also the exclusive property of LESTAGE
Maxime Nathan; its proprietary license terms apply as well.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY DAMAGE, DIRECT OR INDIRECT, ARISING FROM THE USE OF OR INABILITY TO USE THIS
SOFTWARE. USE AT YOUR OWN RISK."),
    ("footer.tagline", "Brocolis messaging 🥦 — selective encryption for your messaging apps. This page mirrors the repository README."),
    ("footer.stack", "Site written in Rust 🦀 and compiled to WebAssembly with Yew."),
    ("footer.credit", "Designed and developed by Maxime Nathan Lestage"),
];

#[rustfmt::skip]
const ES: &[(&str, &str)] = &[
    ("meta.title", "Brocolis 🥦 mensajería — cifrado selectivo"),
    ("meta.desc", "Brocolis mensajería: añade el cifrado selectivo de brocolis a tus apps de mensajería iOS mediante una extensión de compartir. Emparejamiento X25519, clave de grupo, caducidad."),
    ("meta.ogTitle", "Brocolis 🥦 mensajería"),
    ("meta.ogDesc", "Cifrado selectivo para tus mensajerías, basado en brocolis."),
    ("hero.alt", "Brocolis mensajería"),
    ("hero.badge", "iPhone · Apple Watch · Live Activity"),
    ("hero.title", "Tus mensajerías,"),
    ("hero.titleAccent", "cifradas a la carta."),
    ("hero.tagline", tagline!("Cifrado selectivo para tus mensajerías — basado en ", ".")),
    ("cta.repo", "Ver el repositorio"),
    ("cta.brocolis", "Proyecto brocolis"),
    ("cta.server", "Servidor 🛰️"),
    ("cta.salon", "Sala de emparejamiento 🤝"),
    ("cta.pricing", "Ver los planes"),
    ("nav.features", "Funciones"),
    ("nav.pricing", "Planes"),
    ("nav.doc", "Documentación"),
    ("nav.github", "GitHub"),
    ("nav.brocolis", "brocolis"),
    ("nav.menu", "Menú"),
    ("nav.license", "Licencia"),
    ("nav.server", "Servidor"),
    ("nav.salon", "Sala"),
    ("switch.lang", "Idioma"),
    ("switch.theme", "Tema"),
    ("theme.green", "Verde"),
    ("theme.light", "Claro"),
    ("theme.dark", "Oscuro"),
    ("stat.cipher", "AES-256-GCM"),
    ("stat.cipher.d", "por token"),
    ("stat.kex", "X25519"),
    ("stat.kex.d", "emparejamiento"),
    ("stat.server", "0 bytes"),
    ("stat.server.d", "en claro en el servidor"),
    ("features.title", "Todo lo necesario, nada más"),
    ("features.note", "Brocolis se integra en las apps que ya usas y solo cifra lo que tú eliges."),
    ("feat.graft.t", "Se integra en tus apps"),
    ("feat.graft.d", "Extensión de compartir iOS: selecciona texto en WhatsApp, iMessage, Notas… → Compartir → Brocolis 🥦."),
    ("feat.crypto.t", "Cifrado selectivo"),
    ("feat.crypto.d", "Solo los ((secretos)) se vuelven tokens [[BROCOLIS:v1:…]] (AES-256-GCM). El servicio remoto solo ve cifrado."),
    ("feat.pair.t", "Emparejamiento automático"),
    ("feat.pair.d", "Intercambio de claves X25519 con un código corto: cada dispositivo obtiene la clave del otro, sin copiar y pegar."),
    ("feat.group.t", "Clave de grupo"),
    ("feat.group.d", "Un fundador genera una clave de grupo y la distribuye cifrada a cada miembro (key-wrapping X25519)."),
    ("feat.rotate.t", "Rotación y caducidad"),
    ("feat.rotate.d", "Validez configurable, purga automática al abrir, aviso por notificación y acción «Renovar»."),
    ("feat.watch.t", "Apple Watch y Live Activity"),
    ("feat.watch.d", "Sigue tus conversaciones desde el reloj y en la pantalla bloqueada, siempre descifradas en tus dispositivos."),
    ("feat.interop.t", "Compatible con brocolis"),
    ("feat.interop.d", "Mismo formato de token que el proxy Rust brocolis: interoperable en ambos sentidos."),
    ("pricing.title", "Planes"),
    ("pricing.note", "Suscripciones mensuales, sin permanencia: cambia o cancela cuando quieras desde la app (Ajustes → Plan)."),
    ("pricing.month", "/mes"),
    ("pricing.popular", "El más completo"),
    ("pricing.foot", "Recibir una foto o una nota de voz siempre es gratis."),
    ("plan.free.name", "Gratis"),
    ("plan.free.price", "0 €"),
    ("plan.free.f1", "Hasta 3 claves de conversación"),
    ("plan.free.f2", "Mensajes de texto cifrados"),
    ("plan.free.f3", "Emparejamiento, clave de grupo, reloj"),
    ("plan.plus.name", "Brocolis+"),
    ("plan.plus.price", "2,99 €"),
    ("plan.plus.f1", "Claves ilimitadas"),
    ("plan.plus.f2", "Validez de las claves a elegir"),
    ("plan.plus.f3", "Todo lo del plan gratis"),
    ("plan.pro.name", "Brocolis Pro"),
    ("plan.pro.price", "6,99 €"),
    ("plan.pro.f1", "Envío de fotos cifradas"),
    ("plan.pro.f2", "Envío de notas de voz cifradas"),
    ("plan.pro.f3", "Todo lo de Brocolis+"),
    ("doc.title", "Documentación"),
    ("doc.note", "El README del repositorio (en francés)."),
    ("doc.loading", "Cargando README…"),
    ("doc.unavailable", "README no disponible — consulta el repositorio."),
    ("server.title", "Servidor de encuentro"),
    ("server.note", "El espacio dedicado que aloja la API de emparejamiento… y este sitio."),
    ("server.status", "Estado"),
    ("server.checking", "Comprobando…"),
    ("server.online", "En línea"),
    ("server.offline", "Fuera de línea"),
    ("server.latency", "respondió en"),
    ("server.address", "Dirección"),
    ("server.open", "Abrir el servidor"),
    ("server.recheck", "Volver a comprobar"),
    ("server.api", "Puntos de acceso"),
    ("server.api.pair", "intercambio de claves públicas (emparejamiento)"),
    ("server.api.wrap", "distribución de la clave de grupo (cifrada)"),
    ("server.api.health", "estado del servicio"),
    ("server.privacy", "El servidor solo ve claves públicas y blobs cifrados — nunca la clave secreta ni tus mensajes."),
    ("back", "← Volver al inicio"),
    ("salon.title", "Sala de emparejamiento"),
    ("salon.intro", "La sala es donde dos (o más) dispositivos intercambian sus claves públicas para derivar una misma clave secreta — sin enviarla nunca. El servidor solo retransmite lo público; el secreto nunca sale de los teléfonos."),
    ("salon.howTitle", "Cómo funciona"),
    ("salon.step1", "Un dispositivo crea un código corto y muestra su QR / código."),
    ("salon.step2", "El otro introduce el mismo código: cada uno publica su clave pública X25519 en la sala."),
    ("salon.step3", "Cada dispositivo obtiene la clave pública del otro y deriva la MISMA clave secreta (Diffie-Hellman)."),
    ("salon.step4", "Brocolis se activa solo: los mensajes van cifrados con esa clave."),
    ("salon.fingerprint", "Comparad en voz alta la huella de seguridad mostrada en ambos lados: si coincide, nadie interceptó el intercambio (anti-MITM)."),
    ("salon.roomTitle", "Ver una sala en directo"),
    ("salon.roomNote", "Introduce un código para ver quién está presente (solo claves públicas). El emparejamiento real ocurre en la app."),
    ("salon.codeLabel", "Código de la sala"),
    ("salon.codePlaceholder", "p. ej. 4813"),
    ("salon.view", "Ver la sala"),
    ("salon.refreshing", "actualizando…"),
    ("salon.peers", "Participantes"),
    ("salon.empty", "Nadie en esta sala por ahora."),
    ("salon.pub", "clave pública"),
    ("salon.errorTitle", "Sala inaccesible"),
    ("salon.errorCors", "El servidor no es accesible desde este navegador (a menudo CORS cuando la página no la sirve el propio servidor). Prueba desde el sitio alojado por el servidor, o comprueba que está activo."),
    ("salon.privacy", "El servidor solo ve claves públicas y tokens cifrados. Ninguna clave secreta, ningún mensaje en claro."),
    ("license.title", "Licencia"),
    ("license.note", "Texto de la licencia:"),
    ("license.viewFile", "Ver el archivo LICENSE completo →"),
    ("license.full", "Copyright © 2026 LESTAGE Maxime Nathan. Todos los derechos reservados.

Licencia propietaria — All rights reserved.

Este software («Brocolis 🥦», la aplicación iOS, su extensión, el servidor de
encuentro y el sitio web) y su código fuente son propiedad exclusiva de LESTAGE
Maxime Nathan. No pueden ser copiados, modificados, distribuidos, publicados ni
utilizados, en todo o en parte, sin autorización escrita previa del autor.

No se concede ningún derecho, licencia ni título sobre el código fuente.
Cualquier copia, modificación, distribución o uso que infrinja esta licencia
está estrictamente prohibido y es objeto de acciones legales.

Este software acompaña al proyecto brocolis
(https://github.com/maxlestage/brocolis), también propiedad exclusiva de LESTAGE
Maxime Nathan; se aplican igualmente sus términos de licencia propietaria.

EL SOFTWARE SE PROPORCIONA «TAL CUAL», SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O
IMPLÍCITA, INCLUIDAS, ENTRE OTRAS, LAS GARANTÍAS IMPLÍCITAS DE COMERCIABILIDAD Y
ADECUACIÓN A UN FIN DETERMINADO. EN NINGÚN CASO EL AUTOR SERÁ RESPONSABLE DE
NINGÚN DAÑO, DIRECTO O INDIRECTO, DERIVADO DEL USO O LA IMPOSIBILIDAD DE USAR
ESTE SOFTWARE. ÚSALO BAJO TU PROPIA RESPONSABILIDAD."),
    ("footer.tagline", "Brocolis mensajería 🥦 — cifrado selectivo para tus mensajerías. Esta página refleja el README del repositorio."),
    ("footer.stack", "Sitio escrito en Rust 🦀 y compilado a WebAssembly con Yew."),
    ("footer.credit", "Diseñado y desarrollado por Maxime Nathan Lestage"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn keys(table: &'static [(&'static str, &'static str)]) -> BTreeSet<&'static str> {
        table.iter().map(|(k, _)| *k).collect()
    }

    #[test]
    fn every_language_has_the_same_keys() {
        assert_eq!(keys(FR), keys(EN), "FR et EN divergent");
        assert_eq!(keys(FR), keys(ES), "FR et ES divergent");
    }

    #[test]
    fn no_duplicate_keys() {
        for (name, table) in [("fr", FR), ("en", EN), ("es", ES)] {
            assert_eq!(keys(table).len(), table.len(), "doublon dans {name}");
        }
    }

    #[test]
    fn language_codes_round_trip() {
        for l in Lang::ALL {
            assert_eq!(Lang::from_code(l.code()), Some(l));
        }
        assert_eq!(Lang::from_code("en-GB"), Some(Lang::En));
        assert_eq!(Lang::from_code("de"), None);
    }

    #[test]
    fn tagline_links_to_brocolis() {
        for l in Lang::ALL {
            assert!(
                lookup(l.table(), "hero.tagline")
                    .unwrap()
                    .contains(BROCOLIS_LINK)
            );
        }
    }
}
