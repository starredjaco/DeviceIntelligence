pluginManagement {
    includeBuild("deviceintelligence-gradle")
    repositories {
        google()
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

rootProject.name = "DeviceIntelligence"

include(":deviceintelligence")
include(":samples:minimal")
