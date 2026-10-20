// Le remplissage (§3.3, §7.2) : la longueur d'un message ne se lit pas sur
// le jeton. Avant chiffrement : texte ‖ `0x80` ‖ des `0x00` jusqu'au
// multiple de 160 octets suivant (comme Signal). Au déchiffrement : retirer
// les `0x00` de fin puis le `0x80` ; absent → refusé.

public enum Remplissage {
    /// La taille des blocs de remplissage.
    public static let bloc = 160

    /// `données ‖ 0x80 ‖ 0x00…` jusqu'au multiple de 160 suivant (au moins un
    /// octet de remplissage : 159 octets donnent 160, 160 en donnent 320).
    public static func pad(_ data: [UInt8]) -> [UInt8] {
        let length = (data.count / bloc + 1) * bloc
        var out = [UInt8]()
        out.reserveCapacity(length)
        out += data
        out.append(0x80)
        out += [UInt8](repeating: 0, count: length - out.count)
        return out
    }

    /// Retire le remplissage. Refuse (`.remplissage`) une longueur qui n'est
    /// pas un multiple non nul de 160 ou l'absence du `0x80`.
    public static func unpad(_ padded: [UInt8]) throws -> [UInt8] {
        guard !padded.isEmpty, padded.count % bloc == 0 else { throw Erreur.remplissage }
        guard let end = padded.lastIndex(where: { $0 != 0 }), padded[end] == 0x80 else {
            throw Erreur.remplissage
        }
        return Array(padded[0..<end])
    }
}
