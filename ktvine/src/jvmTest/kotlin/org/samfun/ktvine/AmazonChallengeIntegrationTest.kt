package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.host.HostCdmSession
import java.io.File
import java.util.Base64
import kotlin.test.Test

/**
 * Research harness (authorized local DRM research). Builds a Widevine license challenge from a
 * captured Amazon PSSH using a pool WVD and writes it to a local file for the replay driver.
 * Emits only the base64 challenge — no keys, no WVD bytes. Skips unless both system props are set:
 *   -Dwvd.path=<one wvd>  -Damazon.pssh.b64=<pssh>  -Damazon.chal.out=<path>
 */
class AmazonChallengeIntegrationTest {
    @Test
    fun buildAmazonChallenge() = runBlocking {
        val wvd = System.getProperty("wvd.path")?.let(::File)
        val psshB64 = System.getProperty("amazon.pssh.b64")
        val out = System.getProperty("amazon.chal.out")
        if (wvd == null || !wvd.exists() || psshB64.isNullOrBlank() || out.isNullOrBlank()) {
            println("SKIP: set -Dwvd.path -Damazon.pssh.b64 -Damazon.chal.out"); return@runBlocking
        }
        val device = Device.loads(wvd.readBytes())
        val cdm = Cdm.fromDevice(device)
        // Privacy mode: when a service cert is supplied, build the challenge with an ENCRYPTED
        // client_id so the device system_id is hidden (what the Amazon web player does). Amazon's
        // license server REQUEST_BLOCKs a plain client_id that exposes a non-Harley system_id.
        val serviceCertB64 = (System.getProperty("amazon.service_cert.b64")?.takeIf { it.isNotBlank() }
            ?: System.getProperty("amazon.service_cert.path")?.let(::File)?.takeIf { it.exists() }?.readText()?.trim())
            ?.takeIf { it.isNotBlank() }
        val sessionId = cdm.open()
        try {
            val privacy = serviceCertB64 != null
            if (privacy) cdm.setServiceCertificate(sessionId, serviceCertB64)
            val challenge = cdm.getLicenseChallenge(
                sessionId,
                org.samfun.ktvine.core.PSSH(Base64.getDecoder().decode(psshB64)),
                privacyMode = privacy,
            )
            File(out).writeText(Base64.getEncoder().encodeToString(challenge))
            println("AMZ_CHALLENGE_OK bytes=${challenge.size} securityLevel=${device.securityLevel} privacy=$privacy")
        } finally {
            cdm.close(sessionId)
        }
    }

    /**
     * Rotation: build a privacy-mode Amazon challenge for EVERY wvd in a dir, writing
     * <out.dir>/<wvdname>.chal. Lets the replay driver test which (if any) device identity Amazon's
     * web license server accepts. Props: -Dwvd.dir, -Damazon.pssh.b64, -Damazon.service_cert.path,
     * -Damazon.chal.dir [-Damazon.wvd.limit=N].
     */
    @Test
    fun buildAmazonChallengeRotation() = runBlocking {
        val wvdDir = System.getProperty("wvd.dir")?.let(::File)
        val psshB64 = System.getProperty("amazon.pssh.b64")
        val outDir = System.getProperty("amazon.chal.dir")?.let(::File)
        val certB64 = System.getProperty("amazon.service_cert.path")?.let(::File)?.takeIf { it.exists() }?.readText()?.trim()
        if (wvdDir == null || !wvdDir.isDirectory || psshB64.isNullOrBlank() || outDir == null || certB64.isNullOrBlank()) {
            println("SKIP: set -Dwvd.dir -Damazon.pssh.b64 -Damazon.chal.dir -Damazon.service_cert.path"); return@runBlocking
        }
        outDir.mkdirs()
        val limit = System.getProperty("amazon.wvd.limit")?.toIntOrNull() ?: Int.MAX_VALUE
        val pssh = org.samfun.ktvine.core.PSSH(Base64.getDecoder().decode(psshB64))
        var done = 0
        for (wvd in wvdDir.listFiles { f -> f.extension == "wvd" }!!.sortedBy { it.name }) {
            if (done >= limit) break
            try {
                val cdm = Cdm.fromDevice(Device.loads(wvd.readBytes()))
                val sid = cdm.open()
                try {
                    cdm.setServiceCertificate(sid, certB64)
                    val ch = cdm.getLicenseChallenge(sid, pssh, privacyMode = true)
                    File(outDir, wvd.nameWithoutExtension + ".chal").writeText(Base64.getEncoder().encodeToString(ch))
                    done++
                } finally { cdm.close(sid) }
            } catch (e: Throwable) {
                println("WVD_SKIP ${wvd.name}: ${e.message}")
            }
        }
        println("AMZ_ROTATION_OK built=$done -> ${outDir.path}")
    }
}
