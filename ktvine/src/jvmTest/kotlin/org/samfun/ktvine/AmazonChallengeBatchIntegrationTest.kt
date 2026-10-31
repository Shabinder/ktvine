package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.host.HostCdmSession
import java.io.File
import java.util.Base64
import kotlin.test.Test

/**
 * Research harness: emit Widevine challenges for every WVD in a list + one privacy-mode challenge,
 * for the Amazon replay probe (revocation vs structural block). Writes <out>/<wvd-name>.chal and
 * <out>/<wvd-name>.privacy.chal. No keys/WVD bytes printed.
 * Props: -Dwvd.list.file=<file of wvd paths>  -Damazon.pssh.b64=<pssh>  -Damazon.chal.out=<dir>
 */
class AmazonChallengeBatchIntegrationTest {
    @Test
    fun buildBatch() = runBlocking {
        val listFile = System.getProperty("wvd.list.file")?.let(::File)
        val psshB64 = System.getProperty("amazon.pssh.b64")
        val outDir = System.getProperty("amazon.chal.out")?.let(::File)
        if (listFile == null || !listFile.exists() || psshB64.isNullOrBlank() || outDir == null) {
            println("SKIP: set -Dwvd.list.file -Damazon.pssh.b64 -Damazon.chal.out"); return@runBlocking
        }
        outDir.mkdirs()
        val pssh = Base64.getDecoder().decode(psshB64)
        for (line in listFile.readLines().filter { it.isNotBlank() }) {
            val wvd = File(line.trim())
            val name = wvd.nameWithoutExtension
            val device = Device.loads(wvd.readBytes())
            val cdm = Cdm.fromDevice(device)
            // plain challenge (lower Cdm API for direct control)
            val sid1 = cdm.open()
            val plain = cdm.getLicenseChallenge(
                sid1, PSSH(pssh), org.samfun.ktvine.proto.LicenseType.STREAMING, false,
                org.samfun.ktvine.proto.LicenseRequest.RequestType.NEW,
            )
            File(outDir, "$name.chal").writeText(Base64.getEncoder().encodeToString(plain))
            cdm.close(sid1)
            // privacy-mode challenge: client id encrypted to Widevine common cert
            val sid2 = cdm.open()
            cdm.setServiceCertificate(sid2, Cdm.COMMON_PRIVACY_CERT)
            val priv = cdm.getLicenseChallenge(
                sid2, PSSH(pssh), org.samfun.ktvine.proto.LicenseType.STREAMING, true,
                org.samfun.ktvine.proto.LicenseRequest.RequestType.NEW,
            )
            File(outDir, "$name.privacy.chal").writeText(Base64.getEncoder().encodeToString(priv))
            cdm.close(sid2)
            println("CHAL_OK $name level=${device.securityLevel}")
        }
        println("BATCH_DONE")
    }
}
