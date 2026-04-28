plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
}

group = "io.ssemaj"
version = "0.0.0-dev"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // Modern AGP Variant API (8.1+). The plugin only needs the AGP API on the
    // compile classpath; runtime resolution happens in the consumer's build.
    compileOnly("com.android.tools.build:gradle-api:8.13.2")

    // apksig: Google's official APK re-signing library. We use it from
    // InstrumentApkTask (F8) to re-sign the asset-injected APK with the
    // consumer's signingConfig keystore, producing v1+v2+v3 signatures
    // without shelling out to `apksigner`. This is the same library that
    // AGP itself uses internally.
    implementation("com.android.tools.build:apksig:8.13.2")
}

gradlePlugin {
    plugins {
        create("deviceintelligencePlugin") {
            id = "io.ssemaj.deviceintelligence"
            implementationClass = "io.ssemaj.deviceintelligence.gradle.DeviceIntelligencePlugin"
            displayName = "DeviceIntelligence"
            description = "DeviceIntelligence orchestrator: build-time fingerprinting, manifest injection, runtime integrity verification."
        }
    }
}
