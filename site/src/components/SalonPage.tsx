import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useLang } from "../i18n/LangContext";
import type { Lang } from "../i18n/dict";
import { serverBase } from "../config";

// Textes de la page, autonomes (fr/en/es) pour ne pas alourdir le dictionnaire
// global. La page EXPLIQUE le salon de rendez-vous et laisse VOIR, en direct,
// qui est présent sous un code (données publiques : clés publiques uniquement).
const TEXT: Record<Lang, {
  title: string; intro: string;
  howTitle: string; steps: string[];
  fingerprint: string;
  roomTitle: string; roomNote: string;
  codeLabel: string; codePlaceholder: string; view: string; refreshing: string;
  peers: string; empty: string; you: string;
  errorTitle: string; errorCors: string;
  privacy: string; back: string;
}> = {
  fr: {
    title: "Salon des rendez-vous",
    intro:
      "Le salon, c'est l'endroit où deux (ou plusieurs) appareils s'échangent leurs clés publiques pour dériver une même clé secrète — sans jamais l'envoyer. Le serveur ne relaie que du public ; le secret ne quitte jamais les téléphones.",
    howTitle: "Comment ça marche",
    steps: [
      "Un appareil crée un code court et affiche son QR / son code.",
      "L'autre saisit le même code : chacun publie sa clé publique X25519 dans le salon.",
      "Chaque appareil récupère la clé publique de l'autre et dérive la MÊME clé secrète (Diffie-Hellman).",
      "Brocolis s'active tout seul : les messages passent chiffrés avec cette clé.",
    ],
    fingerprint:
      "Comparez de vive voix l'empreinte de sécurité affichée des deux côtés : si elle est identique, personne n'a intercepté l'échange (anti-MITM).",
    roomTitle: "Voir un salon en direct",
    roomNote:
      "Entre un code pour voir qui y est présent (clés publiques seulement). L'appairage réel, lui, se fait dans l'app.",
    codeLabel: "Code du salon",
    codePlaceholder: "ex. 4813",
    view: "Voir le salon",
    refreshing: "actualisation…",
    peers: "Participants",
    empty: "Personne dans ce salon pour l'instant.",
    you: "clé publique",
    errorTitle: "Salon injoignable",
    errorCors:
      "Le serveur n'est pas joignable depuis ce navigateur (souvent : CORS quand la page n'est pas servie par le serveur lui-même). Réessaie depuis le site hébergé par le serveur, ou vérifie qu'il tourne.",
    privacy:
      "Le serveur ne voit que des clés publiques et des jetons chiffrés. Aucune clé secrète, aucun message en clair.",
    back: "← Retour à l'accueil",
  },
  en: {
    title: "Pairing room",
    intro:
      "The room is where two (or more) devices swap public keys to derive one shared secret key — without ever sending it. The server only relays public data; the secret never leaves the phones.",
    howTitle: "How it works",
    steps: [
      "One device creates a short code and shows its QR / code.",
      "The other enters the same code: each publishes its X25519 public key in the room.",
      "Each device fetches the other's public key and derives the SAME secret key (Diffie-Hellman).",
      "Brocolis turns on by itself: messages travel encrypted with that key.",
    ],
    fingerprint:
      "Compare out loud the security fingerprint shown on both sides: if it matches, nobody intercepted the exchange (anti-MITM).",
    roomTitle: "Watch a room live",
    roomNote:
      "Enter a code to see who is present (public keys only). The real pairing happens in the app.",
    codeLabel: "Room code",
    codePlaceholder: "e.g. 4813",
    view: "View room",
    refreshing: "refreshing…",
    peers: "Participants",
    empty: "Nobody in this room yet.",
    you: "public key",
    errorTitle: "Room unreachable",
    errorCors:
      "The server isn't reachable from this browser (often CORS when the page isn't served by the server itself). Try from the site hosted by the server, or check it's running.",
    privacy:
      "The server only sees public keys and encrypted tokens. No secret key, no plaintext message.",
    back: "← Back home",
  },
  es: {
    title: "Sala de emparejamiento",
    intro:
      "La sala es donde dos (o más) dispositivos intercambian sus claves públicas para derivar una misma clave secreta — sin enviarla nunca. El servidor solo retransmite lo público; el secreto nunca sale de los teléfonos.",
    howTitle: "Cómo funciona",
    steps: [
      "Un dispositivo crea un código corto y muestra su QR / código.",
      "El otro introduce el mismo código: cada uno publica su clave pública X25519 en la sala.",
      "Cada dispositivo obtiene la clave pública del otro y deriva la MISMA clave secreta (Diffie-Hellman).",
      "Brocolis se activa solo: los mensajes van cifrados con esa clave.",
    ],
    fingerprint:
      "Comparad en voz alta la huella de seguridad mostrada en ambos lados: si coincide, nadie interceptó el intercambio (anti-MITM).",
    roomTitle: "Ver una sala en directo",
    roomNote:
      "Introduce un código para ver quién está presente (solo claves públicas). El emparejamiento real ocurre en la app.",
    codeLabel: "Código de la sala",
    codePlaceholder: "p. ej. 4813",
    view: "Ver la sala",
    refreshing: "actualizando…",
    peers: "Participantes",
    empty: "Nadie en esta sala por ahora.",
    you: "clave pública",
    errorTitle: "Sala inaccesible",
    errorCors:
      "El servidor no es accesible desde este navegador (a menudo CORS cuando la página no la sirve el propio servidor). Prueba desde el sitio alojado por el servidor, o comprueba que está activo.",
    privacy:
      "El servidor solo ve claves públicas y tokens cifrados. Ninguna clave secreta, ningún mensaje en claro.",
    back: "← Volver al inicio",
  },
};

type Peer = { peerId: string; pub: string };

export function SalonPage() {
  const { lang } = useLang();
  const tx = TEXT[lang];
  const base = serverBase();

  const [code, setCode] = useState("");
  const [active, setActive] = useState<string | null>(null);
  const [peers, setPeers] = useState<Peer[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(false);
  const timer = useRef<number | null>(null);

  const load = useCallback(
    async (c: string) => {
      setRefreshing(true);
      setError(false);
      try {
        const res = await fetch(`${base}/pair?code=${encodeURIComponent(c)}`, {
          signal: AbortSignal.timeout(8000),
        });
        const data = (await res.json()) as { peers?: Peer[] };
        setPeers(Array.isArray(data.peers) ? data.peers : []);
      } catch {
        setError(true);
        setPeers([]);
      } finally {
        setRefreshing(false);
      }
    },
    [base],
  );

  // Rafraîchit toutes les 4 s tant qu'un salon est ouvert.
  useEffect(() => {
    if (!active) return;
    load(active);
    timer.current = window.setInterval(() => load(active), 4000);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [active, load]);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const c = code.trim();
    if (c) setActive(c);
  };

  return (
    <section className="legal salon-page">
      <h1>{tx.title} 🤝</h1>
      <p className="legal-note">{tx.intro}</p>

      <h2>{tx.howTitle}</h2>
      <ol className="salon-steps">
        {tx.steps.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
      <p className="salon-fingerprint">🔑 {tx.fingerprint}</p>

      <h2>{tx.roomTitle}</h2>
      <p className="legal-note">{tx.roomNote}</p>

      <form className="salon-form" onSubmit={submit}>
        <label htmlFor="salon-code">{tx.codeLabel}</label>
        <div className="salon-row">
          <input
            id="salon-code"
            className="salon-input"
            inputMode="text"
            autoComplete="off"
            placeholder={tx.codePlaceholder}
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <button type="submit" className="btn primary" disabled={!code.trim()}>
            {tx.view}
          </button>
        </div>
      </form>

      {active && (
        <div className="salon-room">
          <p className="salon-room-head">
            <strong>{tx.peers}</strong>
            <code className="salon-code-badge">{active}</code>
            {refreshing && <em className="salon-refreshing"> {tx.refreshing}</em>}
          </p>

          {error ? (
            <div className="salon-error">
              <strong>{tx.errorTitle}</strong>
              <p>{tx.errorCors}</p>
            </div>
          ) : peers.length === 0 ? (
            <p className="salon-empty">{tx.empty}</p>
          ) : (
            <ul className="salon-peers">
              {peers.map((p) => (
                <li key={p.peerId}>
                  <span className="salon-peer-id">🥦 {p.peerId}</span>
                  <code className="salon-peer-pub" title={p.pub}>
                    {tx.you}: {p.pub.slice(0, 14)}…
                  </code>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <p className="legal-note">{tx.privacy}</p>
      <p>
        <Link to="/">{tx.back}</Link>
      </p>
    </section>
  );
}
