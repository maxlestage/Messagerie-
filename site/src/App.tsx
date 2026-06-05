import { useEffect, useState } from 'react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';

const REPO_URL = 'https://github.com/maxlestage/Messagerie-';
const BROCOLIS_URL = 'https://github.com/maxlestage/brocolis';

const features = [
  {
    icon: '🧩',
    title: 'Se greffe sur tes apps',
    text: "Extension de partage iOS : sélectionne du texte dans WhatsApp, iMessage, Notes… → Partager → Brocolis 🥦.",
  },
  {
    icon: '🔒',
    title: 'Chiffrement sélectif',
    text: "Seuls les ((secrets)) deviennent des jetons [[BROCOLIS:v1:…]] (AES-256-GCM). Le service distant ne voit que du chiffré.",
  },
  {
    icon: '🤝',
    title: 'Appairage automatique',
    text: "Échange de clés X25519 via un code court : chaque appareil obtient la clé de l’autre, sans copier-coller.",
  },
  {
    icon: '👥',
    title: 'Clé de groupe',
    text: "Un fondateur génère une clé de groupe et la distribue chiffrée à chaque membre (key-wrapping X25519).",
  },
  {
    icon: '⏳',
    title: 'Rotation & expiration',
    text: "Validité configurable, purge automatique à l’ouverture, préavis par notification et action « Prolonger ».",
  },
  {
    icon: '🥦',
    title: 'Compatible brocolis',
    text: "Même format de jeton que le proxy Rust brocolis : interopérable des deux côtés.",
  },
];

export default function App() {
  const [readme, setReadme] = useState<string | null>(null);

  useEffect(() => {
    fetch('README.md')
      .then((r) => (r.ok ? r.text() : Promise.reject(r.status)))
      .then(setReadme)
      .catch(() => setReadme(''));
  }, []);

  return (
    <div className="page">
      <header className="hero">
        <div className="hero-inner">
          <div className="logo">🥦</div>
          <h1>Brocolis</h1>
          <p className="tagline">
            Chiffrement sélectif pour tes messageries — bâti sur{' '}
            <a href={BROCOLIS_URL}>brocolis</a>.
          </p>
          <div className="cta">
            <a className="btn primary" href={REPO_URL}>Voir le dépôt</a>
            <a className="btn" href={BROCOLIS_URL}>Projet brocolis</a>
          </div>
        </div>
      </header>

      <section className="features">
        {features.map((f) => (
          <article className="card" key={f.title}>
            <div className="card-icon">{f.icon}</div>
            <h3>{f.title}</h3>
            <p>{f.text}</p>
          </article>
        ))}
      </section>

      <main className="readme">
        <h2 className="readme-title">Documentation</h2>
        {readme === null ? (
          <p className="loading">Chargement du README…</p>
        ) : readme === '' ? (
          <p className="loading">
            README indisponible — voir le <a href={REPO_URL}>dépôt</a>.
          </p>
        ) : (
          <article className="markdown">
            <Markdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeHighlight]}>
              {readme}
            </Markdown>
          </article>
        )}
      </main>

      <footer className="footer">
        <p>
          Brocolis 🥦 — chiffrement sélectif pour tes messageries, bâti sur{' '}
          <a href={BROCOLIS_URL}>brocolis</a>. Le contenu de cette page reflète le
          README du dépôt.
        </p>
      </footer>
    </div>
  );
}
