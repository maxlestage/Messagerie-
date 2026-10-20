//! Le hasard. En production : le CSPRNG du système, et rien d'autre
//! ([`system`] : `getrandom`, donc `crypto.getRandomValues` dans le
//! navigateur). Toutes les fonctions qui tirent du hasard le reçoivent en
//! paramètre (`&mut impl CryptoRng`), ce qui permet aux vecteurs de test
//! d'injecter [`Deterministic`] : **jamais en production**.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroize;

pub use rand_core::{CryptoRng, Rng};

use crate::kdf::sha256;

/// Le CSPRNG du système. Panique seulement si le système ne peut plus
/// fournir de hasard (aucune entrée ne le provoque).
pub fn system() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

/// Des octets aléatoires.
pub fn bytes<const N: usize>(rng: &mut (impl CryptoRng + ?Sized)) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

/// Un générateur **déterministe**, pour les vecteurs de test et les tests :
/// le bloc `i` (32 octets) vaut `SHA-256("Brocolis_vecteurs" ‖ graine ‖
/// i u64 gros-boutiste)`, `i` partant de 0, et les octets sont servis dans
/// l'ordre, sans en jeter. Les portages peuvent le refaire pour rejouer les
/// vecteurs, mais il ne doit **jamais** servir en production.
#[derive(Clone)]
pub struct Deterministic {
    seed: Vec<u8>,
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl Deterministic {
    /// Un générateur à partir d'une graine (une étiquette lisible suffit).
    pub fn new(seed: &[u8]) -> Self {
        Deterministic {
            seed: seed.to_vec(),
            counter: 0,
            block: [0u8; 32],
            used: 32,
        }
    }

    fn refill(&mut self) {
        let mut input = b"Brocolis_vecteurs".to_vec();
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(&self.counter.to_be_bytes());
        self.block = sha256(&input);
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }
}

impl Drop for Deterministic {
    fn drop(&mut self) {
        self.block.zeroize();
        self.seed.zeroize();
    }
}

impl TryRng for Deterministic {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for byte in dst {
            if self.used == 32 {
                self.refill();
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
        Ok(())
    }
}

// Uniquement pour les tests et les vecteurs (voir plus haut).
impl TryCryptoRng for Deterministic {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministe_et_continu() {
        let mut a = Deterministic::new(b"x");
        let mut b = Deterministic::new(b"x");
        let x: [u8; 40] = bytes(&mut a);
        let mut y = [0u8; 40];
        b.fill_bytes(&mut y[..7]);
        b.fill_bytes(&mut y[7..]);
        assert_eq!(x, y);
        let mut first = b"Brocolis_vecteurs".to_vec();
        first.extend_from_slice(b"x");
        first.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(x[..32], sha256(&first));
    }

    #[test]
    fn systeme() {
        let a: [u8; 32] = bytes(&mut system());
        let b: [u8; 32] = bytes(&mut system());
        assert_ne!(a, b);
    }
}
