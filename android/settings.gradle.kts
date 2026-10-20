pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Brocolis"
include(":app")
// Le protocole v3 (docs/SECURITE.md), porté de proto/ (Rust) ; branché dans
// l'app par crypto/BrocolisV3*.kt (docs/SECURITE.md §8).
include(":proto")
