# DeviceIntelligence

Android telemetry library that collects structured facts about the runtime
environment of the host app — APK integrity, in-process code tampering,
emulator characteristics, and app-cloner indicators — and hands them back
as a single, deterministic JSON report.

DeviceIntelligence is **telemetry, not policy.** It does not block, lock,
crash, or otherwise act on what it sees. It collects facts. Your backend
(or your in-app policy layer) decides what to do with them.

```
DeviceIntelligence.collect(context).toJson()
   ↓
{ schema_version, library_version, device, app, detectors[], summary }
```

## What it collects

| Detector              | id                       | What it observes                                                         |
| --------------------- | ------------------------ | ------------------------------------------------------------------------ |
| APK integrity         | `F10.apk_integrity`      | APK bytes vs. the build-time fingerprint baked by the Gradle plugin      |
| Self-protect watchdog | `F11.self_protect`       | Native code-region drift in `libdicore.so` (in-process patching)         |
| Emulator probe        | `F12.emulator_probe`     | CPU-instruction-level signals (arm64 MRS / x86\_64 CPUID hypervisor bit) |
| App cloner            | `F13.cloner_probe`       | Foreign APK mappings, mount-namespace inconsistencies, UID mismatches    |

Every detector is independent. Adding a new one is a single line in
`TelemetryCollector` and a single class implementing `Detector`.

## Output shape

```json
{
  "schema_version": 1,
  "library_version": "0.1.0-dev",
  "collected_at_epoch_ms": 1777338414219,
  "collection_duration_ms": 277,
  "device": {
    "manufacturer": "Google",
    "model": "Pixel 9 Pro",
    "sdk_int": 36,
    "abi": "arm64-v8a",
    "fingerprint": "google/caiman/caiman:16/CP1A.260405.005/15001963:user/release-keys"
  },
  "app": {
    "package_name": "com.example.app",
    "apk_path": "/data/app/.../base.apk",
    "installer_package": "com.android.vending",
    "signer_cert_sha256": ["a91535782adb..."],
    "build_variant": "release",
    "library_plugin_version": "0.1.0"
  },
  "detectors": [
    {
      "id": "F13.cloner_probe",
      "status": "ok",
      "duration_ms": 2,
      "inconclusive_reason": null,
      "error_message": null,
      "findings": [
        {
          "kind": "running_inside_app_cloner",
          "severity": "critical",
          "subject": "com.example.app",
          "message": "Foreign APK mapping detected in process address space",
          "details": {
            "signal": "foreign_apk_in_maps",
            "expected_package": "com.example.app",
            "foreign_apk_path": "/data/app/.../com.waxmoon.ma.gp-.../base.apk"
          }
        }
      ]
    }
  ],
  "summary": {
    "total_findings": 1,
    "findings_by_severity": { "low": 0, "medium": 0, "high": 0, "critical": 1 },
    "findings_by_kind": { "running_inside_app_cloner": 1 },
    "detectors_with_findings": ["F13.cloner_probe"],
    "detectors_inconclusive": [],
    "detectors_errored": []
  }
}
```

### Stable contract

For each `Finding` these fields are **stable** (safe to key on, alert on,
group by from a backend):

- `kind` — stable identifier
- `severity` — `low` / `medium` / `high` / `critical`. The library *suggests*
  a severity per finding; backends are free to override per their own policy.
- `subject` — what was checked (package name, APK entry, region label)
- `message` — deterministic human-readable one-liner

`details` is **opaque diagnostic data**. Useful for forensics. Its keys may
change between releases without a `schema_version` bump.

## Usage

### 1. Apply the Gradle plugin in your app module

```kotlin
plugins {
    id("io.ssemaj.deviceintelligence")
}

deviceintelligence {
    verbose.set(true)
}

dependencies {
    implementation(project(":deviceintelligence"))
}
```

The plugin runs at build time per variant: it computes a SHA-256 fingerprint
over your APK's entries, encrypts the blob with a per-build XOR key whose
chunks are split across generated Kotlin classes, and injects the encrypted
blob as an asset (`assets/io.ssemaj/fingerprint.bin`) before re-signing the
APK with your `signingConfig` (v1+v2+v3).

### 2. Collect at runtime

```kotlin
val report = DeviceIntelligence.collect(context)        // typed object
val json = DeviceIntelligence.collectJson(context)      // canonical JSON

// Optional: real-time native-text watchdog
DeviceIntelligence.startSelfProtect(
    intervalMs = 1000L,
    listener = SelfProtectListener { drifted ->
        Log.e("MyApp", "Native text drift: $drifted region(s)")
    },
)
```

The library auto-initializes via a manifest-merged `ContentProvider` so
`startSelfProtect` and `collect` are safe to call from any thread without
explicit setup.

## Project layout

```
deviceintelligence/         ← runtime AAR (Kotlin + JNI native lib libdicore.so)
deviceintelligence-gradle/  ← build-time plugin (composite-included)
samples/minimal/            ← sample app: programmatic UI that renders the JSON
tools/                      ← APK build/instrumentation helper scripts
dist/                       ← demo APKs the build scripts produce
```

## Status

Pre-1.0. Wire format `schema_version: 1`. The detector set is stable; the
public Kotlin surface is small (`DeviceIntelligence.collect`,
`DeviceIntelligence.collectJson`, F11 lifecycle, plus the data classes
above) and intentionally won't grow.

## License

```
Copyright 2026 Joseph James (iamjosephmj)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

See the [`LICENSE`](LICENSE) file for the full text.
