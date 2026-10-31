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
        val session = HostCdmSession.open(cdm)
        try {
            val challenge = session.challenge(Base64.getDecoder().decode(psshB64))
            File(out).writeText(Base64.getEncoder().encodeToString(challenge))
            println("AMZ_CHALLENGE_OK bytes=${challenge.size} securityLevel=${device.securityLevel}")
        } finally {
            session.close()
        }
    }
}
