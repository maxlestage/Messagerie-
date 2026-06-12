// Adresse de production du serveur de rendez-vous — la même que celle codée en
// dur dans l'app iOS (BrocolisKeyStore.serverURL). À changer ICI si le serveur
// déménage.
export const SERVER_URL = "https://brocolis-serveur-839b43057467.herokuapp.com";

// Quand la vitrine est servie PAR le serveur lui-même (sur /site/), on
// interroge la même origine : la page Serveur montre alors toujours l'état du
// serveur qui héberge la page. Sinon (dev local, autre hébergement), on
// retombe sur l'adresse de production ci-dessus.
export function serverBase(): string {
  if (window.location.pathname.startsWith("/site")) return window.location.origin;
  return SERVER_URL;
}
