//! Dictionnaire FR / EN / ES. Une table par langue : la même clé doit exister
//! dans les trois (vérifié par les tests en bas du fichier). Partagé par le
//! serveur (rendu des pages) et le navigateur (îlots).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

    /// Une langue exacte (`fr`, `en`, `es`), comme dans les adresses.
    pub fn parse(code: &str) -> Option<Lang> {
        Lang::ALL.into_iter().find(|l| l.code() == code)
    }

    /// Une langue d'après le début d'un code (`en-GB` → anglais).
    pub fn from_code(code: &str) -> Option<Lang> {
        let code = code.trim().to_ascii_lowercase();
        Lang::ALL.into_iter().find(|l| code.starts_with(l.code()))
    }

    /// La langue préférée d'un en-tête `Accept-Language`, le français sinon.
    pub fn pick(accept_language: &str) -> Lang {
        let mut best: Option<(f32, Lang)> = None;
        for part in accept_language.split(',') {
            let mut it = part.split(';');
            let Some(lang) = it.next().and_then(Lang::from_code) else {
                continue;
            };
            let q = it
                .find_map(|p| p.trim().strip_prefix("q="))
                .and_then(|q| q.parse::<f32>().ok())
                .unwrap_or(1.0);
            if best.is_none_or(|(bq, _)| q > bq) {
                best = Some((q, lang));
            }
        }
        best.map_or(Lang::Fr, |(_, l)| l)
    }

    /// Pour Open Graph (`fr_FR`…).
    pub fn og_locale(self) -> &'static str {
        match self {
            Lang::Fr => "fr_FR",
            Lang::En => "en_US",
            Lang::Es => "es_ES",
        }
    }

    fn table(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Lang::Fr => FR,
            Lang::En => EN,
            Lang::Es => ES,
        }
    }

    /// Texte traduit ; retombe sur le français, puis sur « … ».
    pub fn t(self, key: &str) -> &'static str {
        lookup(self.table(), key)
            .or_else(|| lookup(FR, key))
            .unwrap_or("…")
    }
}

fn lookup(table: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Les mots qui défilent dans « Marche dans … » (noms propres, non traduits).
pub const APPS: [&str; 6] = [
    "WhatsApp",
    "iMessage",
    "Messenger",
    "Signal",
    "Notes",
    "Telegram",
];

#[rustfmt::skip]
const FR: &[(&str, &str)] = &[
    ("skip", "Aller au contenu"),
    ("top", "Revenir en haut"),
    ("film.label", "Comment ça marche"),
    ("film.hint", "Fais défiler ↓"),
    ("film.s0", "Un secret, ça se garde."),
    ("film.s1", "Tu écris ton message, comme d'habitude."),
    ("film.s2", "Brocolis le chiffre avant qu'il parte. L'app ne voit que ça."),
    ("film.s3", "Avec l’appairage, la clé ne passe jamais en clair : le salon ne voit que du chiffré."),
    ("film.s4", "Et la conversation te suit jusqu'au poignet."),
    ("film.s5", "Brocolis. Chiffré à la carte."),
    ("meta.title", "Brocolis 🥦 messageries — chiffrement sélectif"),
    ("meta.desc", "Brocolis messageries : ajoute le chiffrement sélectif de brocolis à tes apps de messagerie iOS via une extension de partage. Appairage X25519, clé de groupe, expiration."),
    ("meta.ogTitle", "Brocolis 🥦 messageries"),
    ("meta.ogDesc", "Chiffrement sélectif pour tes messageries, bâti sur brocolis."),
    ("hero.alt", "Brocolis messageries"),
    ("hero.badge", "iPhone · Apple Watch · Live Activity"),
    ("hero.title", "Tes messageries,"),
    ("hero.titleAccent", "chiffrées à la carte."),
    ("hero.tagline", "Chiffrement sélectif pour tes messageries — bâti sur "),
    ("works.label", "Marche dans"),
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
    ("demo.kicker", "Essaie"),
    ("demo.title", "Ce que tu écris, ce que voit l'app"),
    ("demo.note", "Écris un message et entoure tes secrets de ((doubles parenthèses)) : ils deviennent des jetons illisibles, le reste reste en clair."),
    ("demo.input", "Ton message"),
    ("demo.default", "On se retrouve ((à 20h devant le ciné)) ? Le code de la porte : ((4813))."),
    ("demo.plain", "Sur ton téléphone"),
    ("demo.wire", "Ce qui part dans WhatsApp"),
    ("demo.all", "Sans (( )), tout le message est chiffré ; avec, seulement ces passages."),
    ("demo.tokens", "jetons"),
    ("demo.disclaimer", "Démonstration visuelle : ces jetons sont tirés au hasard. Le vrai chiffrement (AES-256-GCM) se fait dans l'app, sur ton téléphone, avec ta clé."),
    ("flow.kicker", "Appairage"),
    ("flow.title", "La clé ne passe jamais en clair"),
    ("flow.note", "Chaque téléphone dépose sa clé publique dans le salon ; celui qui invite crée la clé et la remet chiffrée (X25519) à chacun. À côté : un QR à scanner. Loin : un lien à toucher."),
    ("flow.me", "Ton iPhone"),
    ("flow.them", "Son téléphone"),
    ("flow.server", "Le salon"),
    ("flow.pub", "clé publique"),
    ("flow.secret", "même clé secrète, jamais en clair"),
    ("features.title", "Tout ce qu'il faut, rien de plus"),
    ("features.note", "Brocolis se glisse dans les apps que tu utilises déjà et ne chiffre que ce que tu choisis."),
    ("feat.graft.t", "Se greffe sur tes apps"),
    ("feat.graft.d", "Extension de partage iOS : sélectionne du texte dans WhatsApp, iMessage, Notes… → Partager → Brocolis 🥦."),
    ("feat.crypto.t", "Chiffrement sélectif"),
    ("feat.crypto.d", "Sans marqueur, tout le message est chiffré ; avec des ((…)), seulement ces passages — dans le partage, le clavier et iMessage. Ils deviennent des jetons [[BROCOLIS:v1:…]] (AES-256-GCM) ; le service distant ne voit que du chiffré."),
    ("feat.pair.t", "Appairage automatique"),
    ("feat.pair.d", "« J’invite » / « Je rejoins » : un QR à scanner à côté, un lien à envoyer de loin. Clés X25519, sans copier-coller."),
    ("feat.group.t", "Clé de groupe"),
    ("feat.group.d", "Même geste à plusieurs : celui qui invite génère la clé et la remet chiffrée à chacun, dans n’importe quel ordre (key-wrapping X25519)."),
    ("feat.rotate.t", "Rotation & expiration"),
    ("feat.rotate.d", "Validité configurable (Brocolis+), purge automatique à l’ouverture, préavis par notification et action « Prolonger »."),
    ("feat.watch.t", "Apple Watch & Live Activity"),
    ("feat.watch.d", "Lis et réponds depuis ta montre, déchiffré à ton poignet ; l’écran verrouillé et la Dynamic Island montrent tes messages non lus, jamais leur contenu."),
    ("feat.media.t", "Photos et vocaux, chez Brocolis"),
    ("feat.media.d", "Photos (en miniature, en grand d’un geste) et vocaux d’une minute, chiffrés — uniquement dans la messagerie Brocolis 🥦 : l’app et la discussion en ligne du site. Dans iMessage, WhatsApp & co, Brocolis chiffre le texte, jamais de média."),
    ("feat.interop.t", "Compatible brocolis"),
    ("feat.interop.d", "Même format de jeton que le proxy Rust brocolis : interopérable des deux côtés."),
    ("pricing.title", "Formules"),
    ("pricing.note", "Abonnements mensuels, sans engagement : tu changes ou résilies quand tu veux depuis l’app (section Forfait)."),
    ("pricing.month", "/mois"),
    ("pricing.popular", "Le plus complet"),
    ("pricing.foot", "Recevoir une photo ou un vocal reste toujours gratuit. Photos et vocaux ne s’envoient que dans la messagerie Brocolis 🥦 — l’app, ou la discussion en ligne du site (gratuite) — jamais dans une autre messagerie (iMessage, WhatsApp…), où Brocolis ne chiffre que du texte."),
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
    ("plan.pro.f1", "Envoi de photos chiffrées dans l’app (messagerie Brocolis)"),
    ("plan.pro.f2", "Envoi de vocaux chiffrés (1 min) dans l’app (messagerie Brocolis)"),
    ("plan.pro.f3", "Tout ce qu’offre Brocolis+"),
    ("doc.title", "Documentation"),
    ("doc.note", "Le README du dépôt (en français)."),
    ("doc.more", "Tout lire ↓"),
    ("doc.less", "Replier ↑"),
    ("server.title", "Serveur de rendez-vous"),
    ("server.note", "L'espace dédié qui héberge l'API d'appairage, la messagerie chiffrée… et cette vitrine."),
    ("server.status", "État"),
    ("server.checking", "Vérification…"),
    ("server.online", "En ligne"),
    ("server.offline", "Hors ligne"),
    ("server.latency", "réponse en"),
    ("server.address", "Adresse"),
    ("server.open", "Ouvrir le serveur"),
    ("server.recheck", "Re-vérifier"),
    ("server.chart", "Latence des dernières mesures"),
    ("server.live", "En direct"),
    ("server.stat.messages", "messages chiffrés en transit"),
    ("server.stat.conversations", "conversations actives"),
    ("server.stat.rooms", "salons de rendez-vous ouverts"),
    ("server.stat.listeners", "connexions temps réel"),
    ("server.stat.bytes", "de chiffré en mémoire"),
    ("server.stat.uptime", "en ligne depuis"),
    ("server.memory", "Pas de base de données : les messages chiffrés vivent en mémoire, une semaine au plus. Un redémarrage du serveur les efface définitivement."),
    ("server.stack", "Sous le capot"),
    ("server.stack.paquets", "le framework full-stack qui assemble tout le reste : une crate, une App"),
    ("server.stack.vitesse", "le serveur web, rapide comme son nom (Rust, façon Express)"),
    ("server.stack.securite", "le bouclier devant chaque requête : WAF, CSP, limites de débit, bannissement automatique"),
    ("server.stack.memoire", "les données, en mémoire : ni Postgres ni Redis"),
    ("server.stack.active", "ce site, rendu par le serveur et animé en WebAssembly"),
    ("server.api", "Points d'accès"),
    ("server.api.pair", "échange des clés publiques (appairage)"),
    ("server.api.wrap", "distribution de la clé de groupe (chiffrée)"),
    ("server.api.messages", "messages chiffrés : envoi, historique paginé"),
    ("server.api.stream", "flux temps réel (Server-Sent Events)"),
    ("server.api.stats", "chiffres publics (ceux de cette page)"),
    ("server.api.health", "état du service"),
    ("server.privacy", "Le serveur ne voit que des clés publiques et des blobs chiffrés, jamais la clé secrète ni les messages."),
    ("back", "← Retour à l'accueil"),
    ("salon.title", "Salon des rendez-vous"),
    ("salon.intro", "Le salon, c'est l'endroit où deux (ou plusieurs) appareils se retrouvent — côte à côte ou à l'autre bout du monde — pour partager une même clé secrète. Le serveur ne relaie que des clés publiques et du chiffré : la clé n'y passe jamais en clair."),
    ("salon.howTitle", "Comment ça marche"),
    ("salon.step1", "Celui qui invite touche « J’invite » : un QR et un lien s’affichent."),
    ("salon.step2", "À côté, l'autre scanne le QR ; de loin, il touche le lien reçu. Chacun publie sa clé publique X25519 dans le salon."),
    ("salon.step3", "L'invitant génère la clé et la remet à chacun, chiffrée pour sa clé publique (Diffie-Hellman) : le salon ne voit que du chiffré."),
    ("salon.step4", "Brocolis s'active tout seul : les messages passent chiffrés avec cette clé."),
    ("salon.fingerprint", "Comparez de vive voix l'empreinte de sécurité affichée des deux côtés : si elle est identique, personne n'a intercepté l'échange (anti-MITM)."),
    ("salon.roomTitle", "Voir un salon en direct"),
    ("salon.roomNote", "Entre un code pour voir qui y est présent (clés publiques seulement). L'appairage réel, lui, se fait dans l'app."),
    ("salon.codeLabel", "Code du salon"),
    ("salon.codePlaceholder", "ex. K7P2QX"),
    ("salon.openApp", "Ouvrir dans l’app Brocolis 🥦"),
    ("chat.title", "Discuter en ligne"),
    ("chat.photoSend", "Envoyer une photo chiffrée"),
    ("chat.photoOpen", "Voir la photo en grand"),
    ("chat.close", "Fermer"),
    ("chat.voiceSend", "Enregistrer un vocal chiffré (1 min max)"),
    ("chat.voiceStop", "Arrêter et envoyer le vocal"),
    ("chat.recording", "Enregistrement — touche ⏹ pour envoyer ·"),
    ("chat.micDenied", "Micro refusé ou indisponible : autorise-le dans ton navigateur."),
    ("chat.sendingPhoto", "Photo en cours de chiffrement…"),
    ("nav.chat", "💬 Discuter"),
    ("cta.chat", "Discuter en ligne 💬"),
    ("chat.step1", "Une personne touche « J’invite » : un QR, un code et un lien s’affichent."),
    ("chat.step2", "L’autre scanne le QR, touche le lien ou tape le code — depuis ce site ou depuis l’app (Appairage → Je rejoins)."),
    ("chat.step3", "La clé est partagée chiffrée (X25519) : vous discutez, le serveur ne voit que du chiffré."),
    ("chat.more", "Pour voir qui attend dans un salon, ou ouvrir une invitation dans l’app :"),
    ("chat.intro", "Parle depuis ce navigateur avec quelqu’un — sur le site ou dans l’app — en vous connectant exactement comme dans l’app : « J’invite » ou « Je rejoins ». Tout est chiffré dans la page ; le serveur ne voit que du chiffré. Texte, photos et vocaux (1 min), gratuitement."),
    ("chat.invite", "J’invite"),
    ("chat.join", "Je rejoins"),
    ("chat.inviteHint", "Crée une invitation : un QR à scanner, un code ou un lien à envoyer. L’autre la rejoint depuis le site ou l’app."),
    ("chat.inviteGo", "Créer une invitation"),
    ("chat.joinHint", "Tape le code reçu (ou touche le lien qu’on t’a envoyé)."),
    ("chat.joinGo", "Rejoindre ici"),
    ("chat.qrAlt", "QR code de l’invitation"),
    ("chat.link", "Lien d’invitation"),
    ("chat.copy", "Copier le lien"),
    ("chat.copied", "Lien copié : envoie-le par message."),
    ("chat.copyFailed", "Copie impossible : sélectionne le lien à la main."),
    ("chat.inviteWait", "Garde cette page ouverte : la discussion s’ouvre dès que quelqu’un rejoint (dans l’app : Appairage → Je rejoins)."),
    ("chat.joining", "On attend la clé de la personne qui t’invite…"),
    ("chat.paired", "Appairés · chiffré de bout en bout"),
    ("chat.fingerprint", "Empreinte de sécurité : comparez-la de vive voix"),
    ("chat.leave", "Quitter"),
    ("chat.photo", "Photo chiffrée"),
    ("chat.locked", "🔒 Message chiffré avec une autre clé"),
    ("chat.placeholder", "Écris ton message…"),
    ("chat.send", "Envoyer"),
    ("chat.offline", "Serveur injoignable : réessaie dans un instant."),
    ("chat.someoneJoined", "Quelqu’un de plus a rejoint la discussion."),
    ("salon.view", "Voir le salon"),
    ("salon.refreshing", "actualisation…"),
    ("salon.live", "en direct"),
    ("salon.peers", "Participants"),
    ("salon.empty", "Personne dans ce salon pour l'instant."),
    ("salon.waiting", "On guette les arrivées…"),
    ("salon.pub", "clé publique"),
    ("salon.errorTitle", "Salon injoignable"),
    ("salon.errorCors", "Le serveur n'est pas joignable depuis ce navigateur. Vérifie ta connexion, ou réessaie dans un instant."),
    ("salon.privacy", "Le serveur ne voit que des clés publiques et des jetons chiffrés. Aucune clé secrète, aucun message en clair."),
    ("nf.title", "Page introuvable"),
    ("nf.text", "Cette page s'est chiffrée toute seule. Même nous n'avons pas la clé."),
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
    ("footer.stack", "Site et serveur écrits en Rust 🦀 avec Paquets 📦 : Vitesse pour le web, Securite pour le bouclier, Memoire pour les données, Active pour les pages."),
    ("footer.made", "Écrit avec"),
    ("footer.lock", "Verrouillé par Securite"),
    ("footer.lockText", "Chaque requête passe un pare-feu applicatif (WAF), une limite de débit, un anti-robots et un bannissement automatique ; chaque page part avec une CSP stricte, HSTS et des en-têtes durcis. Et le serveur ne voit jamais que du chiffré."),
    ("footer.packages", "Les paquets"),
    ("footer.credit", "Conçu et développé par Maxime Nathan Lestage"),
];

#[rustfmt::skip]
const EN: &[(&str, &str)] = &[
    ("skip", "Skip to content"),
    ("top", "Back to top"),
    ("film.label", "How it works"),
    ("film.hint", "Scroll ↓"),
    ("film.s0", "A secret should stay one."),
    ("film.s1", "You type your message, as usual."),
    ("film.s2", "Brocolis encrypts it before it leaves. The app only sees this."),
    ("film.s3", "With pairing, the key never travels in the clear: the room only sees ciphertext."),
    ("film.s4", "And the conversation follows you to your wrist."),
    ("film.s5", "Brocolis. Encrypted your way."),
    ("meta.title", "Brocolis 🥦 messaging — selective encryption"),
    ("meta.desc", "Brocolis messaging: adds brocolis selective encryption to your iOS messaging apps via a share extension. X25519 pairing, group key, expiry."),
    ("meta.ogTitle", "Brocolis 🥦 messaging"),
    ("meta.ogDesc", "Selective encryption for your messaging apps, built on brocolis."),
    ("hero.alt", "Brocolis messaging"),
    ("hero.badge", "iPhone · Apple Watch · Live Activity"),
    ("hero.title", "Your messaging apps,"),
    ("hero.titleAccent", "encrypted your way."),
    ("hero.tagline", "Selective encryption for your messaging apps — built on "),
    ("works.label", "Works in"),
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
    ("demo.kicker", "Try it"),
    ("demo.title", "What you write, what the app sees"),
    ("demo.note", "Type a message and wrap your secrets in ((double parentheses)): they turn into unreadable tokens, the rest stays plain."),
    ("demo.input", "Your message"),
    ("demo.default", "Meet you ((at 8pm outside the cinema))? The door code is ((4813))."),
    ("demo.plain", "On your phone"),
    ("demo.wire", "What goes out through WhatsApp"),
    ("demo.all", "Without (( )), the whole message is encrypted; with them, only those parts."),
    ("demo.tokens", "tokens"),
    ("demo.disclaimer", "Visual demo: these tokens are random. The real encryption (AES-256-GCM) happens in the app, on your phone, with your key."),
    ("flow.kicker", "Pairing"),
    ("flow.title", "The key never travels in the clear"),
    ("flow.note", "Each phone drops its public key in the room; the inviter creates the key and hands it to everyone encrypted (X25519). Nearby: a QR to scan. Far away: a link to tap."),
    ("flow.me", "Your iPhone"),
    ("flow.them", "Their phone"),
    ("flow.server", "The room"),
    ("flow.pub", "public key"),
    ("flow.secret", "same secret key, never in the clear"),
    ("features.title", "Everything you need, nothing more"),
    ("features.note", "Brocolis slips into the apps you already use and only encrypts what you choose."),
    ("feat.graft.t", "Hooks into your apps"),
    ("feat.graft.d", "iOS share extension: select text in WhatsApp, iMessage, Notes… → Share → Brocolis 🥦."),
    ("feat.crypto.t", "Selective encryption"),
    ("feat.crypto.d", "Without markers, the whole message is encrypted; with ((…)), only those parts — in Share, the keyboard and iMessage. They become [[BROCOLIS:v1:…]] tokens (AES-256-GCM); the remote service only ever sees ciphertext."),
    ("feat.pair.t", "Automatic pairing"),
    ("feat.pair.d", "“I invite” / “I join”: a QR to scan nearby, a link to send from afar. X25519 keys, no copy-paste."),
    ("feat.group.t", "Group key"),
    ("feat.group.d", "Same gesture for a group: the inviter generates the key and hands it encrypted to each one, in any order (X25519 key-wrapping)."),
    ("feat.rotate.t", "Rotation & expiry"),
    ("feat.rotate.d", "Configurable validity (Brocolis+), auto-purge on launch, an expiry notice and a “Renew” action."),
    ("feat.watch.t", "Apple Watch & Live Activity"),
    ("feat.watch.d", "Read and reply from your watch, decrypted on your wrist; the Lock Screen and Dynamic Island show your unread messages, never their content."),
    ("feat.media.t", "Photos and voice, in Brocolis"),
    ("feat.media.d", "Photos (as thumbnails, full size in one tap) and one-minute voice notes, encrypted — only within Brocolis 🥦 messaging: the app and the site’s online chat. In iMessage, WhatsApp & co, Brocolis encrypts text, never media."),
    ("feat.interop.t", "Brocolis-compatible"),
    ("feat.interop.d", "Same token format as the Rust brocolis proxy: interoperable both ways."),
    ("pricing.title", "Plans"),
    ("pricing.note", "Monthly subscriptions, no commitment: switch or cancel any time from the app (Plan section)."),
    ("pricing.month", "/month"),
    ("pricing.popular", "Most complete"),
    ("pricing.foot", "Receiving a photo or a voice note is always free. Photos and voice notes are only sent within Brocolis 🥦 messaging — the app, or the site’s online chat (free) — never in another messaging app (iMessage, WhatsApp…), where Brocolis only encrypts text."),
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
    ("plan.pro.f1", "Send encrypted photos in the app (Brocolis messaging)"),
    ("plan.pro.f2", "Send encrypted voice notes (1 min) in the app (Brocolis messaging)"),
    ("plan.pro.f3", "Everything in Brocolis+"),
    ("doc.title", "Documentation"),
    ("doc.note", "The repository README (in French)."),
    ("doc.more", "Read it all ↓"),
    ("doc.less", "Fold it back ↑"),
    ("server.title", "Rendezvous server"),
    ("server.note", "The dedicated space hosting the pairing API, the encrypted messaging… and this very site."),
    ("server.status", "Status"),
    ("server.checking", "Checking…"),
    ("server.online", "Online"),
    ("server.offline", "Offline"),
    ("server.latency", "answered in"),
    ("server.address", "Address"),
    ("server.open", "Open the server"),
    ("server.recheck", "Check again"),
    ("server.chart", "Latency of the latest checks"),
    ("server.live", "Live"),
    ("server.stat.messages", "encrypted messages in transit"),
    ("server.stat.conversations", "active conversations"),
    ("server.stat.rooms", "open pairing rooms"),
    ("server.stat.listeners", "real-time connections"),
    ("server.stat.bytes", "of ciphertext in memory"),
    ("server.stat.uptime", "online for"),
    ("server.memory", "No database: encrypted messages live in memory, for a week at most. A server restart wipes them for good."),
    ("server.stack", "Under the hood"),
    ("server.stack.paquets", "the full-stack framework that ties everything together: one crate, one App"),
    ("server.stack.vitesse", "the web server, as fast as its name (Rust, Express-style)"),
    ("server.stack.securite", "the shield in front of every request: WAF, CSP, rate limits, automatic bans"),
    ("server.stack.memoire", "the data, in memory: no Postgres, no Redis"),
    ("server.stack.active", "this site, rendered by the server and animated in WebAssembly"),
    ("server.api", "Endpoints"),
    ("server.api.pair", "public-key exchange (pairing)"),
    ("server.api.wrap", "group-key distribution (encrypted)"),
    ("server.api.messages", "encrypted messages: sending, paginated history"),
    ("server.api.stream", "real-time stream (Server-Sent Events)"),
    ("server.api.stats", "public figures (the ones on this page)"),
    ("server.api.health", "service health"),
    ("server.privacy", "The server only ever sees public keys and encrypted blobs — never the secret key or your messages."),
    ("back", "← Back to home"),
    ("salon.title", "Pairing room"),
    ("salon.intro", "The room is where two (or more) devices meet — side by side or across the world — to share one secret key. The server only relays public keys and ciphertext: the key never passes through it in the clear."),
    ("salon.howTitle", "How it works"),
    ("salon.step1", "The inviter taps “I invite”: a QR and a link appear."),
    ("salon.step2", "Nearby, the other scans the QR; far away, they tap the link. Each publishes its X25519 public key in the room."),
    ("salon.step3", "The inviter generates the key and hands it to each one, encrypted for their public key (Diffie-Hellman): the room only sees ciphertext."),
    ("salon.step4", "Brocolis turns on by itself: messages travel encrypted with that key."),
    ("salon.fingerprint", "Compare out loud the security fingerprint shown on both sides: if it matches, nobody intercepted the exchange (anti-MITM)."),
    ("salon.roomTitle", "Watch a room live"),
    ("salon.roomNote", "Enter a code to see who is present (public keys only). The real pairing happens in the app."),
    ("salon.codeLabel", "Room code"),
    ("salon.codePlaceholder", "e.g. K7P2QX"),
    ("salon.openApp", "Open in the Brocolis 🥦 app"),
    ("chat.title", "Chat online"),
    ("chat.photoSend", "Send an encrypted photo"),
    ("chat.photoOpen", "View the photo full size"),
    ("chat.close", "Close"),
    ("chat.voiceSend", "Record an encrypted voice note (1 min max)"),
    ("chat.voiceStop", "Stop and send the voice note"),
    ("chat.recording", "Recording — tap ⏹ to send ·"),
    ("chat.micDenied", "Microphone denied or unavailable: allow it in your browser."),
    ("chat.sendingPhoto", "Encrypting the photo…"),
    ("nav.chat", "💬 Chat"),
    ("cta.chat", "Chat online 💬"),
    ("chat.step1", "One person taps “I invite”: a QR, a code and a link appear."),
    ("chat.step2", "The other scans the QR, taps the link or types the code — from this site or from the app (Pairing → I join)."),
    ("chat.step3", "The key is shared encrypted (X25519): you chat, the server only sees ciphertext."),
    ("chat.more", "To see who’s waiting in a room, or open an invitation in the app:"),
    ("chat.intro", "Talk from this browser with someone — on the site or in the app — connecting exactly like in the app: “I invite” or “I join”. Everything is encrypted in the page; the server only sees ciphertext. Text, photos and voice notes (1 min), for free."),
    ("chat.invite", "I invite"),
    ("chat.join", "I join"),
    ("chat.inviteHint", "Create an invitation: a QR to scan, a code or a link to send. The other person joins from the site or the app."),
    ("chat.inviteGo", "Create an invitation"),
    ("chat.joinHint", "Type the code you got (or tap the link you were sent)."),
    ("chat.joinGo", "Join here"),
    ("chat.qrAlt", "Invitation QR code"),
    ("chat.link", "Invitation link"),
    ("chat.copy", "Copy the link"),
    ("chat.copied", "Link copied: send it by message."),
    ("chat.copyFailed", "Couldn’t copy: select the link by hand."),
    ("chat.inviteWait", "Keep this page open: the chat opens as soon as someone joins (in the app: Pairing → I join)."),
    ("chat.joining", "Waiting for the inviter’s key…"),
    ("chat.paired", "Paired · end-to-end encrypted"),
    ("chat.fingerprint", "Security fingerprint: compare it out loud"),
    ("chat.leave", "Leave"),
    ("chat.photo", "Encrypted photo"),
    ("chat.locked", "🔒 Message encrypted with another key"),
    ("chat.placeholder", "Type your message…"),
    ("chat.send", "Send"),
    ("chat.offline", "Server unreachable: try again in a moment."),
    ("chat.someoneJoined", "One more person joined the chat."),
    ("salon.view", "View room"),
    ("salon.refreshing", "refreshing…"),
    ("salon.live", "live"),
    ("salon.peers", "Participants"),
    ("salon.empty", "Nobody in this room yet."),
    ("salon.waiting", "Watching for arrivals…"),
    ("salon.pub", "public key"),
    ("salon.errorTitle", "Room unreachable"),
    ("salon.errorCors", "The server can't be reached from this browser. Check your connection, or try again in a moment."),
    ("salon.privacy", "The server only sees public keys and encrypted tokens. No secret key, no plaintext message."),
    ("nf.title", "Page not found"),
    ("nf.text", "This page encrypted itself. Not even we have the key."),
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
    ("footer.stack", "Site and server written in Rust 🦀 with Paquets 📦: Vitesse for the web, Securite for the shield, Memoire for the data, Active for the pages."),
    ("footer.made", "Written with"),
    ("footer.lock", "Locked down by Securite"),
    ("footer.lockText", "Every request goes through a web application firewall (WAF), a rate limit, a bot blocker and automatic bans; every page ships with a strict CSP, HSTS and hardened headers. And the server only ever sees ciphertext."),
    ("footer.packages", "The packages"),
    ("footer.credit", "Designed and developed by Maxime Nathan Lestage"),
];

#[rustfmt::skip]
const ES: &[(&str, &str)] = &[
    ("skip", "Ir al contenido"),
    ("top", "Volver arriba"),
    ("film.label", "Cómo funciona"),
    ("film.hint", "Desplázate ↓"),
    ("film.s0", "Un secreto, se guarda."),
    ("film.s1", "Escribes tu mensaje, como siempre."),
    ("film.s2", "Brocolis lo cifra antes de salir. La app solo ve esto."),
    ("film.s3", "Con el emparejamiento, la clave nunca viaja en claro: la sala solo ve cifrado."),
    ("film.s4", "Y la conversación te sigue hasta la muñeca."),
    ("film.s5", "Brocolis. Cifrado a la carta."),
    ("meta.title", "Brocolis 🥦 mensajería — cifrado selectivo"),
    ("meta.desc", "Brocolis mensajería: añade el cifrado selectivo de brocolis a tus apps de mensajería iOS mediante una extensión de compartir. Emparejamiento X25519, clave de grupo, caducidad."),
    ("meta.ogTitle", "Brocolis 🥦 mensajería"),
    ("meta.ogDesc", "Cifrado selectivo para tus mensajerías, basado en brocolis."),
    ("hero.alt", "Brocolis mensajería"),
    ("hero.badge", "iPhone · Apple Watch · Live Activity"),
    ("hero.title", "Tus mensajerías,"),
    ("hero.titleAccent", "cifradas a la carta."),
    ("hero.tagline", "Cifrado selectivo para tus mensajerías — basado en "),
    ("works.label", "Funciona en"),
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
    ("demo.kicker", "Pruébalo"),
    ("demo.title", "Lo que escribes, lo que ve la app"),
    ("demo.note", "Escribe un mensaje y rodea tus secretos con ((dobles paréntesis)): se vuelven tokens ilegibles, el resto queda en claro."),
    ("demo.input", "Tu mensaje"),
    ("demo.default", "¿Nos vemos ((a las 20h delante del cine))? El código de la puerta: ((4813))."),
    ("demo.plain", "En tu teléfono"),
    ("demo.wire", "Lo que sale por WhatsApp"),
    ("demo.all", "Sin (( )), se cifra todo el mensaje; con ellos, solo esos fragmentos."),
    ("demo.tokens", "tokens"),
    ("demo.disclaimer", "Demostración visual: estos tokens son aleatorios. El cifrado real (AES-256-GCM) ocurre en la app, en tu teléfono, con tu clave."),
    ("flow.kicker", "Emparejamiento"),
    ("flow.title", "La clave nunca viaja en claro"),
    ("flow.note", "Cada teléfono deja su clave pública en la sala; quien invita crea la clave y la entrega cifrada (X25519) a cada uno. Cerca: un QR que escanear. Lejos: un enlace que tocar."),
    ("flow.me", "Tu iPhone"),
    ("flow.them", "Su teléfono"),
    ("flow.server", "La sala"),
    ("flow.pub", "clave pública"),
    ("flow.secret", "misma clave secreta, nunca en claro"),
    ("features.title", "Todo lo necesario, nada más"),
    ("features.note", "Brocolis se integra en las apps que ya usas y solo cifra lo que tú eliges."),
    ("feat.graft.t", "Se integra en tus apps"),
    ("feat.graft.d", "Extensión de compartir iOS: selecciona texto en WhatsApp, iMessage, Notas… → Compartir → Brocolis 🥦."),
    ("feat.crypto.t", "Cifrado selectivo"),
    ("feat.crypto.d", "Sin marcadores, se cifra todo el mensaje; con ((…)), solo esos fragmentos — al compartir, en el teclado y en iMessage. Se vuelven tokens [[BROCOLIS:v1:…]] (AES-256-GCM); el servicio remoto solo ve cifrado."),
    ("feat.pair.t", "Emparejamiento automático"),
    ("feat.pair.d", "«Invito» / «Me uno»: un QR que escanear cerca, un enlace que enviar de lejos. Claves X25519, sin copiar y pegar."),
    ("feat.group.t", "Clave de grupo"),
    ("feat.group.d", "El mismo gesto en grupo: quien invita genera la clave y la entrega cifrada a cada uno, en cualquier orden (key-wrapping X25519)."),
    ("feat.rotate.t", "Rotación y caducidad"),
    ("feat.rotate.d", "Validez configurable (Brocolis+), purga automática al abrir, aviso por notificación y acción «Renovar»."),
    ("feat.watch.t", "Apple Watch y Live Activity"),
    ("feat.watch.d", "Lee y responde desde el reloj, descifrado en tu muñeca; la pantalla bloqueada y la Dynamic Island muestran tus mensajes no leídos, nunca su contenido."),
    ("feat.media.t", "Fotos y audios, en Brocolis"),
    ("feat.media.d", "Fotos (en miniatura, en grande con un gesto) y audios de un minuto, cifrados — solo dentro de la mensajería Brocolis 🥦: la app y el chat en línea del sitio. En iMessage, WhatsApp y demás, Brocolis cifra el texto, nunca medios."),
    ("feat.interop.t", "Compatible con brocolis"),
    ("feat.interop.d", "Mismo formato de token que el proxy Rust brocolis: interoperable en ambos sentidos."),
    ("pricing.title", "Planes"),
    ("pricing.note", "Suscripciones mensuales, sin permanencia: cambia o cancela cuando quieras desde la app (sección Plan)."),
    ("pricing.month", "/mes"),
    ("pricing.popular", "El más completo"),
    ("pricing.foot", "Recibir una foto o un audio siempre es gratis. Fotos y audios solo se envían dentro de la mensajería Brocolis 🥦 — la app, o el chat en línea del sitio (gratis) — nunca en otra mensajería (iMessage, WhatsApp…), donde Brocolis solo cifra texto."),
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
    ("plan.pro.f1", "Envío de fotos cifradas en la app (mensajería Brocolis)"),
    ("plan.pro.f2", "Envío de audios cifrados (1 min) en la app (mensajería Brocolis)"),
    ("plan.pro.f3", "Todo lo de Brocolis+"),
    ("doc.title", "Documentación"),
    ("doc.note", "El README del repositorio (en francés)."),
    ("doc.more", "Leerlo todo ↓"),
    ("doc.less", "Plegar ↑"),
    ("server.title", "Servidor de encuentro"),
    ("server.note", "El espacio dedicado que aloja la API de emparejamiento, la mensajería cifrada… y este sitio."),
    ("server.status", "Estado"),
    ("server.checking", "Comprobando…"),
    ("server.online", "En línea"),
    ("server.offline", "Fuera de línea"),
    ("server.latency", "respondió en"),
    ("server.address", "Dirección"),
    ("server.open", "Abrir el servidor"),
    ("server.recheck", "Volver a comprobar"),
    ("server.chart", "Latencia de las últimas mediciones"),
    ("server.live", "En directo"),
    ("server.stat.messages", "mensajes cifrados en tránsito"),
    ("server.stat.conversations", "conversaciones activas"),
    ("server.stat.rooms", "salas de encuentro abiertas"),
    ("server.stat.listeners", "conexiones en tiempo real"),
    ("server.stat.bytes", "de cifrado en memoria"),
    ("server.stat.uptime", "en línea desde hace"),
    ("server.memory", "Sin base de datos: los mensajes cifrados viven en memoria, una semana como mucho. Reiniciar el servidor los borra definitivamente."),
    ("server.stack", "Bajo el capó"),
    ("server.stack.paquets", "el framework full-stack que lo une todo: una crate, una App"),
    ("server.stack.vitesse", "el servidor web, rápido como su nombre (Rust, al estilo Express)"),
    ("server.stack.securite", "el escudo delante de cada petición: WAF, CSP, límites de tasa, bloqueo automático"),
    ("server.stack.memoire", "los datos, en memoria: ni Postgres ni Redis"),
    ("server.stack.active", "este sitio, renderizado por el servidor y animado en WebAssembly"),
    ("server.api", "Puntos de acceso"),
    ("server.api.pair", "intercambio de claves públicas (emparejamiento)"),
    ("server.api.wrap", "distribución de la clave de grupo (cifrada)"),
    ("server.api.messages", "mensajes cifrados: envío, historial paginado"),
    ("server.api.stream", "flujo en tiempo real (Server-Sent Events)"),
    ("server.api.stats", "cifras públicas (las de esta página)"),
    ("server.api.health", "estado del servicio"),
    ("server.privacy", "El servidor solo ve claves públicas y blobs cifrados — nunca la clave secreta ni tus mensajes."),
    ("back", "← Volver al inicio"),
    ("salon.title", "Sala de emparejamiento"),
    ("salon.intro", "La sala es donde dos (o más) dispositivos se encuentran — juntos o en la otra punta del mundo — para compartir una misma clave secreta. El servidor solo retransmite claves públicas y cifrado: la clave nunca pasa por él en claro."),
    ("salon.howTitle", "Cómo funciona"),
    ("salon.step1", "Quien invita toca «Invito»: aparecen un QR y un enlace."),
    ("salon.step2", "Cerca, el otro escanea el QR; lejos, toca el enlace recibido. Cada uno publica su clave pública X25519 en la sala."),
    ("salon.step3", "Quien invita genera la clave y la entrega a cada uno, cifrada para su clave pública (Diffie-Hellman): la sala solo ve cifrado."),
    ("salon.step4", "Brocolis se activa solo: los mensajes van cifrados con esa clave."),
    ("salon.fingerprint", "Comparad en voz alta la huella de seguridad mostrada en ambos lados: si coincide, nadie interceptó el intercambio (anti-MITM)."),
    ("salon.roomTitle", "Ver una sala en directo"),
    ("salon.roomNote", "Introduce un código para ver quién está presente (solo claves públicas). El emparejamiento real ocurre en la app."),
    ("salon.codeLabel", "Código de la sala"),
    ("salon.codePlaceholder", "p. ej. K7P2QX"),
    ("salon.openApp", "Abrir en la app Brocolis 🥦"),
    ("chat.title", "Chatear en línea"),
    ("chat.photoSend", "Enviar una foto cifrada"),
    ("chat.photoOpen", "Ver la foto en grande"),
    ("chat.close", "Cerrar"),
    ("chat.voiceSend", "Grabar un audio cifrado (1 min máx.)"),
    ("chat.voiceStop", "Parar y enviar el audio"),
    ("chat.recording", "Grabando — toca ⏹ para enviar ·"),
    ("chat.micDenied", "Micrófono denegado o no disponible: permítelo en tu navegador."),
    ("chat.sendingPhoto", "Cifrando la foto…"),
    ("nav.chat", "💬 Chatear"),
    ("cta.chat", "Chatear en línea 💬"),
    ("chat.step1", "Una persona toca «Invito»: aparecen un QR, un código y un enlace."),
    ("chat.step2", "La otra escanea el QR, toca el enlace o escribe el código — desde este sitio o desde la app (Emparejamiento → Me uno)."),
    ("chat.step3", "La clave se comparte cifrada (X25519): chateáis, el servidor solo ve cifrado."),
    ("chat.more", "Para ver quién espera en una sala, o abrir una invitación en la app:"),
    ("chat.intro", "Habla desde este navegador con alguien — en el sitio o en la app — conectándoos igual que en la app: «Invito» o «Me uno». Todo se cifra en la página; el servidor solo ve cifrado. Texto, fotos y audios (1 min), gratis."),
    ("chat.invite", "Invito"),
    ("chat.join", "Me uno"),
    ("chat.inviteHint", "Crea una invitación: un QR que escanear, un código o un enlace que enviar. La otra persona se une desde el sitio o la app."),
    ("chat.inviteGo", "Crear una invitación"),
    ("chat.joinHint", "Escribe el código recibido (o toca el enlace que te enviaron)."),
    ("chat.joinGo", "Unirme aquí"),
    ("chat.qrAlt", "Código QR de la invitación"),
    ("chat.link", "Enlace de invitación"),
    ("chat.copy", "Copiar el enlace"),
    ("chat.copied", "Enlace copiado: envíalo por mensaje."),
    ("chat.copyFailed", "No se pudo copiar: selecciona el enlace a mano."),
    ("chat.inviteWait", "Mantén esta página abierta: el chat se abre en cuanto alguien se une (en la app: Emparejamiento → Me uno)."),
    ("chat.joining", "Esperando la clave de quien te invita…"),
    ("chat.paired", "Emparejados · cifrado de extremo a extremo"),
    ("chat.fingerprint", "Huella de seguridad: comparadla en voz alta"),
    ("chat.leave", "Salir"),
    ("chat.photo", "Foto cifrada"),
    ("chat.locked", "🔒 Mensaje cifrado con otra clave"),
    ("chat.placeholder", "Escribe tu mensaje…"),
    ("chat.send", "Enviar"),
    ("chat.offline", "Servidor inaccesible: reinténtalo en un momento."),
    ("chat.someoneJoined", "Una persona más se unió al chat."),
    ("salon.view", "Ver la sala"),
    ("salon.refreshing", "actualizando…"),
    ("salon.live", "en directo"),
    ("salon.peers", "Participantes"),
    ("salon.empty", "Nadie en esta sala por ahora."),
    ("salon.waiting", "Vigilando las llegadas…"),
    ("salon.pub", "clave pública"),
    ("salon.errorTitle", "Sala inaccesible"),
    ("salon.errorCors", "No se puede contactar con el servidor desde este navegador. Comprueba tu conexión o vuelve a intentarlo en un momento."),
    ("salon.privacy", "El servidor solo ve claves públicas y tokens cifrados. Ninguna clave secreta, ningún mensaje en claro."),
    ("nf.title", "Página no encontrada"),
    ("nf.text", "Esta página se cifró sola. Ni siquiera nosotros tenemos la clave."),
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
    ("footer.stack", "Sitio y servidor escritos en Rust 🦀 con Paquets 📦: Vitesse para la web, Securite para el escudo, Memoire para los datos, Active para las páginas."),
    ("footer.made", "Escrito con"),
    ("footer.lock", "Blindado por Securite"),
    ("footer.lockText", "Cada petición pasa por un cortafuegos de aplicaciones (WAF), un límite de tasa, un bloqueador de robots y bloqueos automáticos; cada página sale con una CSP estricta, HSTS y cabeceras reforzadas. Y el servidor solo ve texto cifrado."),
    ("footer.packages", "Los paquetes"),
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
            assert_eq!(Lang::parse(l.code()), Some(l));
            assert_eq!(Lang::from_code(l.code()), Some(l));
        }
        assert_eq!(Lang::from_code("en-GB"), Some(Lang::En));
        assert_eq!(Lang::from_code("de"), None);
        assert_eq!(Lang::parse("en-GB"), None);
    }

    #[test]
    fn accept_language_picks_the_best_known_language() {
        assert_eq!(Lang::pick("es-ES,es;q=0.9,en;q=0.8"), Lang::Es);
        assert_eq!(Lang::pick("de-DE,de;q=0.9,en;q=0.5"), Lang::En);
        assert_eq!(Lang::pick("de"), Lang::Fr);
        assert_eq!(Lang::pick(""), Lang::Fr);
        assert_eq!(Lang::pick("fr;q=0.2, en;q=0.9"), Lang::En);
    }

    #[test]
    fn the_demo_text_has_secrets_to_encrypt() {
        for l in Lang::ALL {
            assert!(l.t("demo.default").contains("(("), "{l:?}");
        }
    }
}
