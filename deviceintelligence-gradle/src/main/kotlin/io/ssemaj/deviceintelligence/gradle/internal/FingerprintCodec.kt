package io.ssemaj.deviceintelligence.gradle.internal

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream

/**
 * Compact binary serializer/deserializer for [Fingerprint].
 *
 * Format (network byte order, JDK [DataOutputStream] semantics):
 *
 *   uint32  magic           = 0x52615370 ('DeviceIntelligence')
 *   uint32  formatVersion   = [FORMAT_VERSION]; bumped on wire-format change
 *   uint32  schemaVersion   = Fingerprint.SCHEMA_VERSION
 *   int64   builtAtEpochMs
 *   utf8    pluginVersion
 *   utf8    variantName
 *   utf8    applicationId
 *   uint32  signerCertCount
 *     utf8  certHex      [signerCertCount times]
 *   uint32  entryCount
 *     utf8  entryName    [entryCount times]
 *     utf8  entryHashHex [entryCount times]
 *   uint32  ignoredEntryCount
 *     utf8  name         [ignoredEntryCount times]
 *   uint32  ignoredPrefixCount
 *     utf8  prefix       [ignoredPrefixCount times]
 *   utf8    expectedSourceDirPrefix
 *   uint32  installerWhitelistCount
 *     utf8  installer    [installerWhitelistCount times]
 *
 * The format is intentionally trivial: no length-prefixed envelopes, no CBOR
 * tags, no varints. The runtime decoder mirrors this byte-for-byte using
 * [DataInputStream]; both ends agree on the schema purely by code inspection.
 *
 * Why not Protobuf/CBOR/MessagePack? Two reasons:
 *  1. Zero new dependencies on either side (plugin classpath stays clean,
 *     the runtime AAR doesn't pull in a 100KB serializer).
 *  2. The schema is tiny (~10 fields) and stable; the cost of a hand-rolled
 *     codec is ~30 lines per side.
 */
internal object FingerprintCodec {

    const val MAGIC: Int = 0x52615370 // 'DeviceIntelligence'
    const val FORMAT_VERSION: Int = 1

    fun encode(fp: Fingerprint, out: OutputStream) {
        DataOutputStream(out).run {
            writeInt(MAGIC)
            writeInt(FORMAT_VERSION)
            writeInt(fp.schemaVersion)
            writeLong(fp.builtAtEpochMs)
            writeUTF(fp.pluginVersion)
            writeUTF(fp.variantName)
            writeUTF(fp.applicationId)

            writeInt(fp.signerCertSha256.size)
            for (cert in fp.signerCertSha256) writeUTF(cert)

            // Entries are written in sorted key order so the on-disk bytes
            // are deterministic for the same logical input. This matters
            // when callers want to byte-compare two fingerprints.
            val sortedKeys = fp.entries.keys.sorted()
            writeInt(sortedKeys.size)
            for (k in sortedKeys) {
                writeUTF(k)
                writeUTF(fp.entries.getValue(k))
            }

            writeInt(fp.ignoredEntries.size)
            for (e in fp.ignoredEntries) writeUTF(e)

            writeInt(fp.ignoredEntryPrefixes.size)
            for (p in fp.ignoredEntryPrefixes) writeUTF(p)

            writeUTF(fp.expectedSourceDirPrefix)

            writeInt(fp.expectedInstallerWhitelist.size)
            for (i in fp.expectedInstallerWhitelist) writeUTF(i)

            flush()
        }
    }

    fun decode(input: InputStream): Fingerprint {
        DataInputStream(input).run {
            val magic = readInt()
            require(magic == MAGIC) {
                "Fingerprint blob magic mismatch: 0x${magic.toUInt().toString(16)} != 0x52615370"
            }
            val formatVersion = readInt()
            require(formatVersion == FORMAT_VERSION) {
                "Fingerprint blob format version $formatVersion not supported (expected $FORMAT_VERSION)"
            }

            val schemaVersion = readInt()
            val builtAtEpochMs = readLong()
            val pluginVersion = readUTF()
            val variantName = readUTF()
            val applicationId = readUTF()

            val certCount = readInt()
            val certs = ArrayList<String>(certCount).apply {
                repeat(certCount) { add(readUTF()) }
            }

            val entryCount = readInt()
            val entries = LinkedHashMap<String, String>(entryCount).apply {
                repeat(entryCount) {
                    val name = readUTF()
                    val hash = readUTF()
                    put(name, hash)
                }
            }

            val ignoredCount = readInt()
            val ignored = ArrayList<String>(ignoredCount).apply {
                repeat(ignoredCount) { add(readUTF()) }
            }

            val prefixCount = readInt()
            val prefixes = ArrayList<String>(prefixCount).apply {
                repeat(prefixCount) { add(readUTF()) }
            }

            val sourceDirPrefix = readUTF()

            val installerCount = readInt()
            val installers = ArrayList<String>(installerCount).apply {
                repeat(installerCount) { add(readUTF()) }
            }

            return Fingerprint(
                schemaVersion = schemaVersion,
                builtAtEpochMs = builtAtEpochMs,
                pluginVersion = pluginVersion,
                variantName = variantName,
                applicationId = applicationId,
                signerCertSha256 = certs,
                entries = entries,
                ignoredEntries = ignored,
                ignoredEntryPrefixes = prefixes,
                expectedSourceDirPrefix = sourceDirPrefix,
                expectedInstallerWhitelist = installers,
            )
        }
    }
}
