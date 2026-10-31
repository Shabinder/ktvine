package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseType
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * End-to-end "export-to-raw": real Widevine device -> live Google test license
 * (proxy.widevine.com, public Tears of Steel content) -> the AUDIO content key
 * (KID nil UUID) -> CENC fragmented-MP4 audio decrypted with the production
 * CencStreamDecryptor body (vendored verbatim, javax AES/CTR) -> mdat payloads
 * byte-match the public clear reference.
 *
 * Run with `:ktvine:integrationTest`, e.g.
 * `-Dexport.run.dir=$HOME/ktvine/ktvine/build/export-to-raw-run`.
 */
class ExportToRawIntegrationTest {

    @Test
    fun `export-to-raw decrypts CENC audio byte-exact vs clear reference`() {
        runBlocking {
            val data = TestFixtures.orSkip("device/widevine/google_avd.wvd") ?: return@runBlocking

            val runDir = File(
                System.getProperty(
                    "export.run.dir",
                    File(File(System.getProperty("user.home")), "ktvine").path + "/ktvine/build/export-to-raw-run",
                ),
            )

            val enc = File(runDir, "tears_audio_eng.cenc.mp4")
            if (!enc.exists()) {
                println("SKIP: no CENC audio at $enc (run -Dexport.run.dir)")
                return@runBlocking
            }
            val clearRef = File(runDir, "tears_audio_eng.clear.mp4")
            require(clearRef.exists()) { "clear reference missing at $clearRef" }

            val device = Device.loads(data)
            val cdm = Cdm.fromDevice(device)
            val sessionId = cdm.open()

            val mpd = TestFixtures.readText("playlist/tears.mpd")
            val psshB64 = requireNotNull(Regex("""<cenc:pssh\b[^>]*>([^<]+)</cenc:pssh>""").find(mpd)?.groupValues?.getOrNull(1)?.trim()) {
                "No cenc:pssh found in MPD"
            }
            val pssh = PSSH(psshB64)

            val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING)

            val url = URI.create("https://proxy.widevine.com/proxy").toURL()
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/octet-stream")
                setRequestProperty("Accept", "application/octet-stream")
                connectTimeout = 15000
                readTimeout = 30000}
            conn.outputStream.use { it.write(challenge) }
            val response = conn.inputStream.use { it.readBytes() }

            cdm.parseLicense(sessionId, response)

            // The audio key is the one under the nil UUID KID (the license's other
            // CONTENT keys are the SD/HD video KIDs). Key bytes stay in the heap;
            // counts/sizes only on the console.
            val contentKeys = cdm.getKeys(sessionId, License.KeyContainer.KeyType.CONTENT)
            val audioKey = contentKeys.single { it.kid.toString() == "00000000-0000-0000-0000-000000000000" }.key

            val out = Cenc.decryptAndRemux(enc.readBytes(), audioKey)

            val outStr = String(out, Charsets.ISO_8859_1)
            for (box in listOf("senc", "sinf", "saiz", "saio", "pssh", "enca")) {
                check(!outStr.contains(box)) { "protection box $box survived in output" }
            }

            val a = mdatPayloads(out)
            val b = mdatPayloads(clearRef.readBytes())
            check(a.isNotEmpty()) { "no mdat in decrypted output" }
            check(a.contentEquals(b)) {
                "decrypted mdat differs from clear reference (out=${a.size} ref=${b.size})"
            }

            println("EXPORT_TO_RAW_OK mdatBytes=${a.size} matchesClearReference=true boxesStripped=true")
        }
    }

    /**
     * Phase 3: device-pool rotation. Walks the gitignored pool, classifies each device as
     * accepted/rejected by the live proxy (paced, capped), and proves a byte-exact export from the
     * FIRST accepted device after any rejected ones. Prints counts only — never keys or device ids.
     * Run: `-Dwvd.pool.dir=$HOME/.config/soundbound/wvd -Dexport.run.dir=...`.
     */
    @Test
    fun `device rotation exports byte-exact from the first accepted pool device`() {
        runBlocking {
            val poolDir = System.getProperty("wvd.pool.dir")?.let(::File)
            if (poolDir == null || !poolDir.isDirectory) {
                println("SKIP: set -Dwvd.pool.dir to run Phase 3 rotation.")
                return@runBlocking
            }
            val runDir = File(System.getProperty("export.run.dir", File(File(System.getProperty("user.home")), "ktvine").path + "/ktvine/build/export-to-raw-run"))
            val enc = File(runDir, "tears_audio_eng.cenc.mp4")
            val clearRef = File(runDir, "tears_audio_eng.clear.mp4")
            if (!enc.exists() || !clearRef.exists()) {
                println("SKIP: CENC/clear fixtures missing in $runDir.")
                return@runBlocking
            }

            val mpd = TestFixtures.readText("playlist/tears.mpd")
            val pssh = PSSH(requireNotNull(Regex("""<cenc:pssh\b[^>]*>([^<]+)</cenc:pssh>""").find(mpd)?.groupValues?.getOrNull(1)?.trim()))
            val clearMdat = mdatPayloads(clearRef.readBytes())

            // Cap probes so the public proxy is not hammered; this proves rotation, not a full census.
            val cap = (System.getProperty("rotation.cap")?.toIntOrNull() ?: 5)
            val devices = (poolDir.listFiles { f -> f.extension == "wvd" }?.sortedBy { it.name } ?: emptyList()).take(cap)
            check(devices.size >= 2) { "need >=2 pool devices to prove rotation" }

            var accepted = 0
            var rejected = 0
            var exportedFrom = -1
            for ((idx, f) in devices.withIndex()) {
                val outcome = runCatching {
                    val cdm = Cdm.fromDevice(Device.loads(f.readBytes()))
                    val sessionId = cdm.open()
                    val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING)
                    val conn = (URI.create("https://proxy.widevine.com/proxy").toURL().openConnection() as HttpURLConnection).apply {
                        requestMethod = "POST"; doOutput = true; connectTimeout = 15000; readTimeout = 30000
                        setRequestProperty("Content-Type", "application/octet-stream")
                    }
                    conn.outputStream.use { it.write(challenge) }
                    if (conn.responseCode != 200) return@runCatching false
                    cdm.parseLicense(sessionId, conn.inputStream.use { it.readBytes() })
                    val key = cdm.getKeys(sessionId, License.KeyContainer.KeyType.CONTENT)
                        .single { it.kid.toString() == "00000000-0000-0000-0000-000000000000" }.key
                    val out = Cenc.decryptAndRemux(enc.readBytes(), key)
                    check(mdatPayloads(out).contentEquals(clearMdat)) { "export mismatch from accepted device" }
                    true
                }.getOrDefault(false)
                if (outcome) { accepted++; if (exportedFrom < 0) exportedFrom = idx } else rejected++
                Thread.sleep(1000) // pacing between probes
            }

            println("ROTATION probed=${devices.size} accepted=$accepted rejected=$rejected exportedFromIndex=$exportedFrom")
            check(exportedFrom >= 0) { "no pool device produced a byte-exact export" }
            println("DEVICE_ROTATION_OK")
        }
    }

    private fun mdatPayloads(b: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        var i = 0
        while (i + 8 <= b.size) {
            val size = ((b[i].toInt() and 255) shl 24) or ((b[i + 1].toInt() and 255) shl 16) or
                ((b[i + 2].toInt() and 255) shl 8) or (b[i + 3].toInt() and 255)
            if (size < 8) break
            if (String(b, i + 4, 4, Charsets.ISO_8859_1) == "mdat") out.write(b, i + 8, size - 8)
            i += size
        }
        return out.toByteArray()
    }

    /** Vendored verbatim from CencStreamDecryptor (drops decryptInPlace/DecryptionSpec/okio). */
    private object Cenc {
        private fun u32(b: ByteArray, i: Int): Long =
            ((b[i].toLong() and 255) shl 24) or ((b[i + 1].toLong() and 255) shl 16) or
                ((b[i + 2].toLong() and 255) shl 8) or (b[i + 3].toLong() and 255)

        private fun u16(b: ByteArray, i: Int): Int =
            ((b[i].toInt() and 255) shl 8) or (b[i + 1].toInt() and 255)

        private fun type(b: ByteArray, i: Int): String =
            String(charArrayOf(b[i].toInt().toChar(), b[i + 1].toInt().toChar(),
                b[i + 2].toInt().toChar(), b[i + 3].toInt().toChar()))

        private data class Box(val type: String, val start: Int, val size: Int) {
            val contentStart get() = start + 8
            val end get() = start + size
        }

        private fun children(b: ByteArray, start: Int, end: Int): List<Box> {
            val out = ArrayList<Box>()
            var p = start
            while (p + 8 <= end) {
                val size = u32(b, p).toInt()
                require(size in 8..(end - p)) { "bad box size $size at $p" }
                out.add(Box(type(b, p + 4), p, size))
                p += size
            }
            require(p == end) { "trailing bytes in container" }
            return out
        }

        private data class Sample(val offset: Int, val size: Int, val iv: ByteArray?, val subsamples: List<Pair<Int, Int>>)

        fun decryptAndRemux(enc: ByteArray, key: ByteArray): ByteArray {
            val top = children(enc, 0, enc.size)
            val clearDescriptions = clearAudioDescriptions(enc, top)
            var pending: List<Sample>? = null
            val outBoxes = ArrayList<ByteArray>()
            for (box in top) {
                when (box.type) {
                    "moof" -> { pending = samplesOf(enc, box, clearDescriptions); outBoxes.add(rebuild(enc, box.start)) }
                    "mdat" -> {
                        val samples = requireNotNull(pending) { "mdat without preceding moof" }
                        pending = null
                        val clear = ByteArray(box.size - 8)
                        var w = 0
                        for (s in samples) {
                            val plain = if (s.iv == null) enc.copyOfRange(s.offset, s.offset + s.size)
                                else cencDecrypt(key, s.iv, enc, s.offset, s.size, s.subsamples)
                            plain.copyInto(clear, w); w += plain.size
                        }
                        require(w == clear.size) { "sample payloads != mdat size" }
                        outBoxes.add(boxBytes("mdat", clear))
                    }
                    else -> outBoxes.add(rebuild(enc, box.start))
                }
            }
            val out = ByteArrayOutputStream(outBoxes.sumOf { it.size })
            for (b in outBoxes) out.write(b)
            return out.toByteArray()
        }

        private fun clearAudioDescriptions(b: ByteArray, top: List<Box>): Set<Long> {
            fun child(parent: Box, name: String): Box = children(b, parent.contentStart, parent.end).single { it.type == name }
            val moov = top.single { it.type == "moov" }
            val trak = child(moov, "trak") // Multiple tracks remain unsupported.
            val stbl = child(child(child(trak, "mdia"), "minf"), "stbl")
            val stsd = child(stbl, "stsd")
            return children(b, stsd.contentStart + 8, stsd.end).mapIndexedNotNull { index, entry ->
                if (entry.type in setOf("mp4a", "fLaC", "Opus", "alac")) index.toLong() + 1 else null
            }.toSet()
        }

        private fun samplesOf(b: ByteArray, moof: Box, clearDescriptions: Set<Long>): List<Sample> {
            val traf = children(b, moof.contentStart, moof.end).first { it.type == "traf" }
            val kids = children(b, traf.contentStart, traf.end)
            val trun = kids.first { it.type == "trun" }
            val senc = kids.firstOrNull { it.type == "senc" }

            val trunFlags = (u32(b, trun.contentStart) and 0xffffff).toInt()
            val sampleCount = u32(b, trun.contentStart + 4).toInt()
            var tp = trun.contentStart + 8
            val dataOffset = if (trunFlags and 0x1 != 0) { val v = u32(b, tp).toInt(); tp += 4; v } else 0
            if (trunFlags and 0x4 != 0) tp += 4
            val sizes = IntArray(sampleCount)
            resolveSizes(b, tp, trunFlags, sizes)

            // Shaka's public Tears of Steel fixture starts with a clear lead fragment:
            // tfhd selects sample_description_index=2 (clear), without senc/saiz/saio.
            if (senc == null) {
                val tfhd = kids.first { it.type == "tfhd" }
                val flags = (u32(b, tfhd.contentStart) and 0xffffff).toInt()
                var at = tfhd.contentStart + 8
                if (flags and 1 != 0) at += 8
                require(flags and 2 != 0 && u32(b, at) in clearDescriptions) { "Missing sample encryption metadata" }
                var offset = moof.start + dataOffset
                return sizes.map { size -> Sample(offset, size, null, emptyList()).also { offset += size } }
            }

            val sencFlags = (u32(b, senc.contentStart) and 0xffffff).toInt()
            val count = u32(b, senc.contentStart + 4).toInt()
            require(count == sampleCount) { "senc/trun count mismatch" }
            val ivSize = ivSize(b, traf)
            var sp = senc.contentStart + 8
            val samples = ArrayList<Sample>(count)
            var dataCursor = moof.start + dataOffset
            for (i in 0 until count) {
                val iv = ByteArray(16)
                b.copyInto(iv, 0, sp, sp + ivSize); sp += ivSize
                val subs = ArrayList<Pair<Int, Int>>()
                if (sencFlags and 0x2 != 0) {
                    val subCount = u16(b, sp); sp += 2
                    repeat(subCount) {
                        val cl = u16(b, sp); val pr = u32(b, sp + 2).toInt(); sp += 6
                        subs.add(cl to pr)
                    }
                }
                samples.add(Sample(dataCursor, sizes[i], iv, subs))
                dataCursor += sizes[i]
            }
            return samples
        }

        private fun entryStride(flags: Int): Int =
            (if (flags and 0x100 != 0) 4 else 0) + (if (flags and 0x200 != 0) 4 else 0) +
                (if (flags and 0x400 != 0) 4 else 0) + (if (flags and 0x800 != 0) 4 else 0)

        private fun resolveSizes(b: ByteArray, entriesStart: Int, flags: Int, sizes: IntArray) {
            val stride = entryStride(flags)
            require(flags and 0x200 != 0) { "trun must carry sample sizes (0x200)" }
            val sizeFieldOffset = if (flags and 0x100 != 0) 4 else 0
            for (i in sizes.indices) sizes[i] = u32(b, entriesStart + i * stride + sizeFieldOffset).toInt()
        }

        private fun ivSize(b: ByteArray, traf: Box): Int {
            val saiz = children(b, traf.contentStart, traf.end).firstOrNull { it.type == "saiz" } ?: return 16
            val defaultSize = b[saiz.contentStart + 4].toInt() and 255
            return if (defaultSize == 8 || defaultSize == 16) defaultSize else 16
        }

        /** javax AES/CTR over the protected ranges (continuous counter across subsamples). */
        private fun cencDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray, offset: Int, size: Int,
                                subsamples: List<Pair<Int, Int>>): ByteArray {
            val sample = data.copyOfRange(offset, offset + size)
            if (subsamples.isEmpty()) return aesCtr(key, iv, sample)
            // Subsample CENC: only the protected ranges are encrypted and they concatenate into one
            // continuous CTR keystream, so each protected range starts encBytes into the stream and may
            // be mid-block (javax can't seed a mid-block counter directly -> aesCtrUnaligned).
            val out = sample.copyOf()
            var pos = 0
            var encBytes = 0L
            for ((clear, prot) in subsamples) {
                pos += clear
                if (prot > 0) {
                    aesCtrUnaligned(key, iv, encBytes, sample.copyOfRange(pos, pos + prot)).copyInto(out, pos)
                    pos += prot
                    encBytes += prot
                }
            }
            require(pos == sample.size) { "subsample ranges != sample size" }
            return out
        }

        private fun aesCtr(key: ByteArray, counter: ByteArray, input: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/CTR/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(counter))
            return c.doFinal(input)
        }

        /** Decrypt [input] whose CTR keystream starts [byteOffset] bytes into the stream from [iv]. */
        private fun aesCtrUnaligned(key: ByteArray, iv: ByteArray, byteOffset: Long, input: ByteArray): ByteArray {
            val skip = (byteOffset % 16).toInt()
            val counter = advanceCounter(iv, byteOffset / 16)
            val padded = ByteArray(skip + input.size)
            input.copyInto(padded, skip)
            return aesCtr(key, counter, padded).copyOfRange(skip, skip + input.size)
        }

        private fun advanceCounter(iv: ByteArray, blocks: Long): ByteArray {
            val counter = iv.copyOf()
            var carry = blocks
            for (i in 15 downTo 0) {
                val sum = (counter[i].toInt() and 255) + (carry and 255).toInt()
                counter[i] = sum.toByte()
                carry = (carry ushr 8) + (sum ushr 8)
            }
            require(carry == 0L) { "CTR overflow" }
            return counter
        }

        private val CONTAINERS = setOf("moov", "trak", "mdia", "minf", "stbl", "dinf", "mvex", "udta", "moof", "traf", "edts")

        private fun rebuild(b: ByteArray, boxStart: Int): ByteArray {
            val size = u32(b, boxStart).toInt()
            val t = type(b, boxStart + 4)
            val cs = boxStart + 8
            val ce = boxStart + size
            return when (t) {
                // Segment byte offsets change when protection metadata is removed.
                "senc", "saiz", "saio", "sinf", "pssh", "sidx" -> ByteArray(0)
                "enca", "encv" -> {
                    val original = originalFormat(b, boxStart)
                    val fixed = b.copyOfRange(cs, cs + 28)
                    boxBytes(original, fixed + rebuildChildren(b, cs + 28, ce))
                }
                "stsd" -> boxBytes("stsd", b.copyOfRange(cs, cs + 8) + rebuildChildren(b, cs + 8, ce))
                "traf" -> {
                    val newKids = rebuildChildren(b, cs, ce)
                    patchTrunDataOffset(newKids, (ce - cs) - newKids.size)
                    boxBytes("traf", newKids)
                }
                in CONTAINERS -> boxBytes(t, rebuildChildren(b, cs, ce))
                else -> b.copyOfRange(boxStart, ce)
            }
        }

        private fun rebuildChildren(b: ByteArray, start: Int, end: Int): ByteArray {
            val out = ByteArrayOutputStream()
            for (box in children(b, start, end)) out.write(rebuild(b, box.start))
            return out.toByteArray()
        }

        private fun originalFormat(b: ByteArray, encaStart: Int): String {
            for (box in children(b, encaStart + 8 + 28, encaStart + u32(b, encaStart).toInt())) {
                if (box.type == "sinf") {
                    for (c in children(b, box.contentStart, box.end)) if (c.type == "frma") return type(b, c.contentStart)
                }
            }
            error("enca without sinf/frma original_format")
        }

        private fun patchTrunDataOffset(traf: ByteArray, removed: Int) {
            var p = 0
            while (p + 8 <= traf.size) {
                val size = u32(traf, p).toInt()
                if (type(traf, p + 4) == "trun") {
                    val flags = (u32(traf, p + 8) and 0xffffff).toInt()
                    require(flags and 0x1 != 0) { "trun has no data_offset to patch" }
                    val at = p + 16
                    val v = u32(traf, at).toInt() - removed
                    traf[at] = (v ushr 24).toByte(); traf[at + 1] = (v ushr 16).toByte()
                    traf[at + 2] = (v ushr 8).toByte(); traf[at + 3] = v.toByte()
                    return
                }
                p += size
            }
            error("no trun in traf")
        }

        private fun boxBytes(t: String, content: ByteArray): ByteArray {
            val size = 8 + content.size
            val out = ByteArray(size)
            out[0] = (size ushr 24).toByte(); out[1] = (size ushr 16).toByte()
            out[2] = (size ushr 8).toByte(); out[3] = size.toByte()
            for (i in 0..3) out[4 + i] = t[i].code.toByte()
            content.copyInto(out, 8)
            return out
        }
    }
}
