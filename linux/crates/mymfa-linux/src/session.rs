/*
 * Sessions de transfert du Secret Service : comment un secret voyage sur le bus.
 *
 *  - `plain` : en clair (le bus de session est local à l'utilisateur) ;
 *  - `dh-ietf1024-sha256-aes128-cbc-pkcs7` : échange Diffie-Hellman sur le
 *    groupe MODP 1024 bits d'Oakley (RFC 2409 §6.2, générateur 2), secret
 *    partagé complété à 128 octets, clé AES-128 = HKDF-SHA256(sel vide, info
 *    vide), puis chaque secret en AES-128-CBC/PKCS#7 avec un IV aléatoire
 *    porté par `parameters` — l'algorithme de libsecret et de gnome-keyring.
 */
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use num_bigint::BigUint;
use zeroize::Zeroizing;

pub const PLAIN: &str = "plain";
pub const DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// Premier du groupe 2 (RFC 2409 §6.2).
const PREMIER_1024: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

fn premier() -> BigUint {
    BigUint::parse_bytes(PREMIER_1024.as_bytes(), 16).expect("premier RFC 2409")
}

pub enum Chiffrement {
    Clair,
    Aes128 { cle: Zeroizing<[u8; 16]> },
}

/// Secret tel qu'il circule : (session, paramètres, valeur, type de contenu).
pub type SecretDbus = (zbus::zvariant::OwnedObjectPath, Vec<u8>, Vec<u8>, String);

#[derive(Debug, PartialEq, Eq)]
pub enum ErreurSession {
    AlgorithmeInconnu,
    ClePublique,
    Dechiffrement,
}

/// Ouvre une session : rend le chiffrement et la sortie à renvoyer au client
/// (vide pour `plain`, notre clé publique pour DH).
pub fn negocier(algorithme: &str, entree: &[u8]) -> Result<(Chiffrement, Vec<u8>), ErreurSession> {
    match algorithme {
        PLAIN => Ok((Chiffrement::Clair, Vec::new())),
        DH => {
            let p = premier();
            let leur = BigUint::from_bytes_be(entree);
            // Clé publique dégénérée (0, 1, p-1, ≥ p) : refusée.
            if leur <= BigUint::from(1u32) || leur >= &p - 1u32 {
                return Err(ErreurSession::ClePublique);
            }
            let prive = Zeroizing::new(mymfa_core::vault::random_bytes(128));
            let x = BigUint::from_bytes_be(&prive);
            let notre = BigUint::from(2u32).modpow(&x, &p);
            let partage = Zeroizing::new(leur.modpow(&x, &p).to_bytes_be());
            Ok((Chiffrement::Aes128 { cle: cle_aes(&partage) }, notre.to_bytes_be()))
        }
        _ => Err(ErreurSession::AlgorithmeInconnu),
    }
}

/// HKDF-SHA256 du secret partagé complété à gauche jusqu'à 128 octets.
fn cle_aes(partage: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut complet = Zeroizing::new(vec![0u8; 128usize.saturating_sub(partage.len())]);
    complet.extend_from_slice(partage);
    let mut cle = Zeroizing::new([0u8; 16]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, &complet)
        .expand(&[], cle.as_mut())
        .expect("16 octets tiennent dans HKDF-SHA256");
    cle
}

impl Chiffrement {
    /// (paramètres, valeur) pour un secret en clair.
    pub fn chiffrer(&self, secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            Chiffrement::Clair => (Vec::new(), secret.to_vec()),
            Chiffrement::Aes128 { cle } => {
                let iv = mymfa_core::vault::random_bytes(16);
                let chiffre = cbc::Encryptor::<aes::Aes128>::new(cle.as_ref().into(), iv.as_slice().into())
                    .encrypt_padded_vec_mut::<Pkcs7>(secret);
                (iv, chiffre)
            }
        }
    }

    pub fn dechiffrer(&self, parametres: &[u8], valeur: &[u8]) -> Result<Zeroizing<Vec<u8>>, ErreurSession> {
        match self {
            Chiffrement::Clair => Ok(Zeroizing::new(valeur.to_vec())),
            Chiffrement::Aes128 { cle } => {
                if parametres.len() != 16 {
                    return Err(ErreurSession::Dechiffrement);
                }
                cbc::Decryptor::<aes::Aes128>::new(cle.as_ref().into(), parametres.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(valeur)
                    .map(Zeroizing::new)
                    .map_err(|_| ErreurSession::Dechiffrement)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Côté client, comme libsecret : notre propre paire, puis le même calcul.
    fn client(cle_publique_serveur: &[u8], prive: &[u8]) -> Chiffrement {
        let p = premier();
        let partage = BigUint::from_bytes_be(cle_publique_serveur).modpow(&BigUint::from_bytes_be(prive), &p).to_bytes_be();
        Chiffrement::Aes128 { cle: cle_aes(&partage) }
    }

    #[test]
    fn plain() {
        let (c, sortie) = negocier(PLAIN, &[]).unwrap();
        assert!(sortie.is_empty());
        let (params, valeur) = c.chiffrer(b"secret");
        assert!(params.is_empty());
        assert_eq!(c.dechiffrer(&params, &valeur).unwrap().as_slice(), b"secret");
    }

    #[test]
    fn diffie_hellman_aller_retour() {
        let prive = mymfa_core::vault::random_bytes(128);
        let publique = BigUint::from(2u32).modpow(&BigUint::from_bytes_be(&prive), &premier()).to_bytes_be();
        let (serveur, sortie) = negocier(DH, &publique).unwrap();
        let cote_client = client(&sortie, &prive);
        // Serveur → client
        let (iv, ct) = serveur.chiffrer("mot de passe Wi-Fi".as_bytes());
        assert_eq!(iv.len(), 16);
        assert_ne!(ct, b"mot de passe Wi-Fi");
        assert_eq!(cote_client.dechiffrer(&iv, &ct).unwrap().as_slice(), "mot de passe Wi-Fi".as_bytes());
        // Client → serveur
        let (iv, ct) = cote_client.chiffrer(b"");
        assert_eq!(serveur.dechiffrer(&iv, &ct).unwrap().as_slice(), b"");
        assert_eq!(serveur.dechiffrer(&iv[..8], &ct).unwrap_err(), ErreurSession::Dechiffrement);
    }

    #[test]
    fn cles_degenerees_refusees() {
        assert_eq!(negocier(DH, &[1]).err(), Some(ErreurSession::ClePublique));
        assert_eq!(negocier(DH, &[]).err(), Some(ErreurSession::ClePublique));
        assert_eq!(negocier(DH, &(premier() - 1u32).to_bytes_be()).err(), Some(ErreurSession::ClePublique));
        assert_eq!(negocier("aes-gcm-inconnu", &[]).err(), Some(ErreurSession::AlgorithmeInconnu));
    }
}
