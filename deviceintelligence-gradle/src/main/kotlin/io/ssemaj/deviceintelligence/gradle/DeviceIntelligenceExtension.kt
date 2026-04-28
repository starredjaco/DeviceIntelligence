package io.ssemaj.deviceintelligence.gradle

import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty

/**
 * Consumer-facing DSL block. Real options (reaction policy, detector set,
 * pepper, etc.) layer on in subsequent flags. For now this is a stable
 * placeholder so the plugin applies and the DSL block is reachable.
 */
abstract class DeviceIntelligenceExtension {
    /** Plugin verbosity at configuration time. */
    abstract val verbose: Property<Boolean>

    /** Reserved for the detector toggle set; unused at L4. */
    abstract val detectors: SetProperty<String>
}
