//! Un double cliquet en miniature, pour la page « Protocole v3 » : ce n'est
//! pas de la cryptographie, seulement sa comptabilité — quelles clés existent
//! encore quand un espion copie l'état, et lesquelles sont déjà effacées.
//! Même logique que le simulateur du site brocolis.

/// Le nombre de lignes de chaque côté (`proto.sim.you.*`, `proto.sim.alice.*`).
pub const SIM_LINES: usize = 8;

/// Qui écrit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Who {
    You,
    Alice,
}

/// Ce qui s'affiche dans le fil du simulateur.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// Un message : son auteur, l'époque du cliquet (un échange
    /// Diffie-Hellman), son rang dans la chaîne, et sa ligne de texte (le
    /// rang de ses messages à lui).
    Msg {
        from: Who,
        epoch: u32,
        n: u32,
        line: usize,
    },
    /// Le grand cliquet tourne : l'autre a répondu.
    Turn,
    /// Un espion copie l'état de **votre** ordinateur.
    Spy,
}

/// Ce que l'espion peut faire d'un message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Exposure {
    /// Parti avant la copie : sa clé était effacée.
    Past,
    /// Lisible avec l'état copié.
    Exposed,
    /// Parti après que le cliquet a tourné de votre côté : clé inconnue.
    Healed,
}

/// Un double cliquet en miniature, pour voir où passe la frontière : ce
/// n'est pas de la cryptographie, seulement sa comptabilité.
///
/// L'état copié contient votre clé de cliquet courante. L'espion lit donc la
/// chaîne en cours **et**, si c'est vous qui avez écrit en dernier, la
/// réponse d'Alice (elle est dérivée de votre clé de cliquet). Il perd tout
/// dès que vous tirez une clé de cliquet neuve, c'est-à-dire à votre
/// prochain envoi après une réponse : la session a guéri.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sim {
    pub events: Vec<Event>,
    epoch: u32,
    n: u32,
    last: Option<Who>,
    sent: usize,
    /// Messages envoyés par vous, par Alice.
    by: [usize; 2],
    /// L'époque copiée, et qui avait écrit en dernier à ce moment-là.
    spy: Option<(usize, u32, Who)>,
}

impl Sim {
    pub fn sent(&self) -> usize {
        self.sent
    }

    pub fn spied(&self) -> bool {
        self.spy.is_some()
    }

    /// Envoie la ligne suivante ; `false` quand il n'y en a plus.
    pub fn send(&mut self, from: Who) -> bool {
        if self.sent >= SIM_LINES {
            return false;
        }
        match self.last {
            Some(last) if last == from => {}
            Some(_) => {
                self.epoch += 1;
                self.n = 0;
                self.events.push(Event::Turn);
            }
            None => {}
        }
        self.last = Some(from);
        self.n += 1;
        let line = &mut self.by[from as usize];
        self.events.push(Event::Msg {
            from,
            epoch: self.epoch,
            n: self.n,
            line: *line,
        });
        *line += 1;
        self.sent += 1;
        true
    }

    /// L'espion copie l'état (une fois, après au moins un message).
    pub fn spy(&mut self) -> bool {
        let Some(last) = self.last else { return false };
        if self.spy.is_some() {
            return false;
        }
        self.spy = Some((self.events.len(), self.epoch, last));
        self.events.push(Event::Spy);
        true
    }

    /// Ce que l'espion fait du `i`-ième événement (un message).
    pub fn exposure(&self, i: usize) -> Option<Exposure> {
        let (at, epoch, last) = self.spy?;
        let Event::Msg { epoch: e, .. } = *self.events.get(i)? else {
            return None;
        };
        Some(if i < at {
            Exposure::Past
        } else if e == epoch || (last == Who::You && e == epoch + 1) {
            Exposure::Exposed
        } else {
            Exposure::Healed
        })
    }

    /// Messages lisibles par l'espion.
    pub fn exposed(&self) -> usize {
        (0..self.events.len())
            .filter(|&i| self.exposure(i) == Some(Exposure::Exposed))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rien_de_ce_qui_est_parti_avant_la_copie_n_est_lisible() {
        let mut s = Sim::default();
        assert!(!s.spy(), "pas d'espion avant le premier message");
        s.send(Who::You); // K1·1
        s.send(Who::You); // K1·2
        assert!(s.spy());
        assert!(!s.spy(), "une seule copie");
        s.send(Who::You); // K1·3 : même chaîne, lisible
        s.send(Who::Alice); // K2·1 : dérivée de ma clé de cliquet copiée
        s.send(Who::You); // K3·1 : clé de cliquet neuve, guéri
        s.send(Who::Alice); // K4·1 : guéri
        let x: Vec<_> = (0..s.events.len()).filter_map(|i| s.exposure(i)).collect();
        assert_eq!(
            x,
            [
                Exposure::Past,
                Exposure::Past,
                Exposure::Exposed,
                Exposure::Exposed,
                Exposure::Healed,
                Exposure::Healed
            ]
        );
        assert_eq!(s.exposed(), 2);
        assert_eq!(s.sent(), 6);
    }

    #[test]
    fn copie_apres_une_reponse_alice_seule_est_exposee() {
        let mut s = Sim::default();
        s.send(Who::You);
        s.send(Who::Alice);
        s.spy();
        s.send(Who::Alice); // même chaîne qu'Alice : lisible
        s.send(Who::You); // je tourne le cliquet : guéri
        let x: Vec<_> = (0..s.events.len()).filter_map(|i| s.exposure(i)).collect();
        assert_eq!(
            x,
            [
                Exposure::Past,
                Exposure::Past,
                Exposure::Exposed,
                Exposure::Healed
            ]
        );
    }

    #[test]
    fn le_fil_s_arrete_a_la_derniere_ligne() {
        let mut s = Sim::default();
        for i in 0..SIM_LINES {
            assert!(s.send(if i % 2 == 0 { Who::You } else { Who::Alice }));
        }
        assert!(!s.send(Who::You));
        let turns = s.events.iter().filter(|e| **e == Event::Turn).count();
        assert_eq!(
            turns,
            SIM_LINES - 1,
            "le cliquet tourne à chaque changement d'auteur"
        );
    }
}
