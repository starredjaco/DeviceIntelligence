// Top-level build file. Plugins are declared here as `apply false` and applied
// in the relevant subprojects.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
}
