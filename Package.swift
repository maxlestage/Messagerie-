// swift-tools-version:5.9
// BrocolisProto : le protocole de sécurité de Brocolis 🥦 et Talka
// (docs/SECURITE.md), porté en Swift depuis l'implémentation de référence
// Rust (proto/). Il retrouve ses vecteurs (proto/vectors.json) octet pour
// octet et passe les vecteurs Wycheproof des primitives
// (proto/tests/wycheproof/).
//
// Le paquet est à la racine du dépôt pour que d'autres apps (Talka…) en
// dépendent par l'URL du dépôt et une révision ; ses sources sont dans
// proto-swift/. L'app Brocolis le prend par son chemin (project.yml :
// `packages: BrocolisProto: path: .`) : l'app, le clavier, Partager et
// iMessage parlent v3 (docs/SECURITE.md §8).
//
// CryptoKit sur les plateformes Apple ; ailleurs (Linux : les tests),
// swift-crypto, la même API. ML-KEM-768 vient de CryptoKit à partir
// d'iOS 26 / macOS 26 (sinon le mode hybride répond `pqIndisponible`), et de
// swift-crypto 4 sous Linux.
import PackageDescription

let package = Package(
    name: "BrocolisProto",
    platforms: [.iOS(.v16), .macOS(.v13), .watchOS(.v9), .tvOS(.v16), .visionOS(.v1)],
    products: [
        .library(name: "BrocolisProto", targets: ["BrocolisProto"]),
    ],
    dependencies: [
        // Utilisé seulement hors des plateformes Apple (voir la condition
        // plus bas). 4.x : la première série qui offre MLKEM768.
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(
            name: "BrocolisProto",
            dependencies: [
                .product(
                    name: "Crypto", package: "swift-crypto",
                    condition: .when(platforms: [.linux, .android, .windows])),
            ],
            path: "proto-swift/Sources/BrocolisProto"),
        // Les tests lisent les vecteurs du dépôt lui-même (proto/vectors.json,
        // proto/tests/wycheproof/) et Fixtures/ par leur chemin : une seule
        // source, jamais de copie périmée.
        .testTarget(
            name: "BrocolisProtoTests",
            dependencies: ["BrocolisProto"],
            path: "proto-swift/Tests/BrocolisProtoTests",
            exclude: ["Fixtures"]),
    ]
)
