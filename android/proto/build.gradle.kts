// Module :proto — le protocole de sécurité de Brocolis 🥦 et Talka
// (docs/SECURITE.md), porté en Kotlin depuis l'implémentation de référence
// Rust (proto/). Il retrouve ses vecteurs (proto/vectors.json) octet pour
// octet et passe les vecteurs Wycheproof des primitives
// (proto/tests/wycheproof/) : `gradle :proto:testDebugUnitTest`.
//
// Bibliothèque Android sans aucune dépendance à `android.*` : tout le code se
// teste tel quel sur la JVM. Primitives : BouncyCastle (X25519, Ed25519,
// ML-KEM-768, Argon2id, HKDF, HMAC, SHA-256, PBKDF2) et javax.crypto
// (AES-256-GCM), jamais réécrites ici.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "rs.brocolis.messagerie.proto"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    testOptions {
        unitTests.all {
            // Argon2id au défaut (64 Mio) et les états de session copiés à
            // chaque déchiffrement : un peu de marge.
            it.maxHeapSize = "1g"
            it.testLogging {
                events("failed")
                showStandardStreams = true
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }
}

dependencies {
    // 1.79 est la première série conforme à FIPS 203 final (ML-KEM) ; 1.86
    // offre aussi l'encapsulation déterministe (`internalGenerateEncapsulated`)
    // et le contrôle du module d'une clé ML-KEM reçue.
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    // Les états (appareil, sessions, chaînes de groupe) en JSON, de la même
    // forme que la référence Rust (serde_json) : l'arbre JsonElement suffit,
    // sans le greffon de sérialisation.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    testImplementation("junit:junit:4.13.2")
}
