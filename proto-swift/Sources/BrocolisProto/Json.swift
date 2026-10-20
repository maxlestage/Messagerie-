// Les états sérialisés en JSON, **de la même forme que la référence Rust**
// (serde) : mêmes noms de champs (snake_case), octets en base64 standard,
// `null` pour une option vide (écrit, jamais omis : serde l'exige pour les
// champs `serde_b64::opt`), énumérations par leur nom (`"Hybrid"`). Un état
// écrit par l'une se relit par l'autre ; l'ordre des champs peut différer
// (sans effet en JSON).

import Foundation

enum Json {
    static func encode<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
        guard let data = try? encoder.encode(value) else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    /// Relit un état ; toute erreur devient `.etat`.
    static func decode<T: Decodable>(_ type: T.Type, _ text: String) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: Data(text.utf8))
        } catch {
            throw Erreur.etat
        }
    }
}

extension KeyedDecodingContainer {
    /// Des octets en base64 strict, de longueur `length` si elle est donnée
    /// (`[u8; N]` côté Rust).
    func bytes(_ key: Key, length: Int? = nil) throws -> [UInt8] {
        let text = try decode(String.self, forKey: key)
        guard let b = Base64.decode(text), length.map({ b.count == $0 }) ?? true else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "base64 ou longueur")
        }
        return b
    }

    /// Des octets optionnels : le champ doit être présent (`null` ou base64),
    /// comme `serde_b64::opt` sans `default`.
    func optionalBytes(_ key: Key, length: Int? = nil) throws -> [UInt8]? {
        if try decodeNil(forKey: key) { return nil }
        return try bytes(key, length: length)
    }
}

extension KeyedEncodingContainer {
    mutating func encodeBytes(_ value: [UInt8], forKey key: Key) throws {
        try encode(Base64.encode(value), forKey: key)
    }

    /// Une option : base64 ou `null` (jamais omise).
    mutating func encodeOptionalBytes(_ value: [UInt8]?, forKey key: Key) throws {
        if let value { try encodeBytes(value, forKey: key) } else { try encodeNil(forKey: key) }
    }

    /// Un entier optionnel : nombre ou `null`.
    mutating func encodeOptional<T: Encodable>(_ value: T?, forKey key: Key) throws {
        if let value { try encode(value, forKey: key) } else { try encodeNil(forKey: key) }
    }
}
