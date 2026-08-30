import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

// Signature de release — DEUX sources possibles, jamais commitées (voir ../.gitignore) :
// - `keystore.properties` à la racine de ce module Gradle, pour un build release fait à la main en
//   local (storeFile/storePassword/keyAlias/keyPassword, 4 lignes `clé=valeur`) ;
// - sinon les variables d'environnement ANDROID_KEYSTORE_PATH/ANDROID_KEYSTORE_PASSWORD/
//   ANDROID_KEY_ALIAS/ANDROID_KEY_PASSWORD, lues en CI (voir .github/workflows/release-android.yml,
//   qui décode le secret ANDROID_KEYSTORE_BASE64 vers un fichier temporaire puis exporte ces 4
//   variables avant `./gradlew assembleRelease`).
// Sans AUCUNE des deux sources (ex: `npm run tauri android dev`, ou un clone frais sans ces
// secrets), `signingConfigs.getByName("release")` reste avec des champs `null` — Gradle produira
// alors un release NON SIGNÉ plutôt que d'échouer la commande : seul `assembleRelease` en vue
// d'une vraie publication a besoin d'une signature valide, pas chaque build local.
val keystorePropertiesFile = file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

android {
    compileSdk = 36
    namespace = "com.julie.passmanager"
    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            } else {
                System.getenv("ANDROID_KEYSTORE_PATH")?.let { storeFile = file(it) }
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "com.julie.passmanager"
        minSdk = 24
        targetSdk = 36
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            // CORRECTIF COMPATIBILITÉ : par défaut, Android bloque le trafic HTTP non chiffré pour
            // un build "release" (usesCleartextTraffic = false hérité de defaultConfig ci-dessus).
            // Cette app pointe vers une URL de backend choisie par l'UTILISATEUR À L'EXÉCUTION (voir
            // lib/settings.ts::getBackendUrl — auto-hébergement, jamais une adresse fixée au build),
            // souvent un serveur local (ex: "http://192.168.x.x:3000") sans certificat TLS — sans ce
            // réglage, TOUS les appels réseau échoueraient silencieusement sur un build release.
            // Cohérent avec la CSP déjà en place (`connect-src ... http: https: ws: wss:`, voir
            // tauri.conf.json) qui autorise déjà explicitement le HTTP non chiffré côté JS.
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = "tauri.build.gradle.kts")