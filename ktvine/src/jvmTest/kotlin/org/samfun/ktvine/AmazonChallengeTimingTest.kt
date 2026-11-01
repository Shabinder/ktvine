package org.samfun.ktvine

import kotlinx.coroutines.test.runTest
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.host.HostCdmOwner
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.measureTime

/**
 * Isolates the Amazon playback hang: does ktvine's challenge path block on the real Amazon
 * entitlement PSSH + a real WVD? If this returns fast, the on-device hang is bridge/dispatcher, not
 * ktvine; if it hangs here, it's ktvine's handling of the Amazon GROUP_PSSH.
 */
class AmazonChallengeTimingTest {

    // Real captured values (2026-11-01). Plain cid: pssh + ROBIN_CONTENT:IN entitlement GROUP_PSSH.
    private val plainPssh =
        "AAAAXXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAD0SEPgpHEcL4JRq08qZ56Xy0DwaC0FtYXpvbk11c2ljIhxjaWQ6K0NrY1J3dmdsR3JUeXBubnBmTFFQQT09"
    private val robinPssh =
        "AAAAsnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAJIiHGNpZDo3ZGd4TnZmTVoxU1Y5eEVpSFBXYTVRPT04AFAAWAJqEFJPQklOX0NPTlRFTlQ6SU5yWgoQ7dgxNvfMZ1SV9xEiHPWa5RIQ+CkcRwvglGrTypnnpfLQPBog6WVAyBcO3zh2+Zai9+GQDOl5HoRnd7bRNtuM+1iJnnUiEOc8R/3Yl4jlWPCzgnPHQQooIA=="

    private fun loadDevice(): Device {
        val bytes = AmazonChallengeTimingTest::class.java.getResourceAsStream("/amazon_test.wvd")!!.readBytes()
        return Device.loads(bytes)
    }

    @Test
    fun plainPsshChallengeIsFast() = runTest {
        val owner = HostCdmOwner(Cdm.fromDevice(loadDevice()))
        val s = owner.open()
        val t = measureTime {
            val ch = s.challenge(java.util.Base64.getDecoder().decode(plainPssh))
            assertTrue(ch.isNotEmpty())
        }
        println("PLAIN_CHALLENGE_MS=${t.inWholeMilliseconds}")
        owner.release(s)
        assertTrue(t.inWholeMilliseconds < 10_000, "plain pssh challenge took ${t.inWholeMilliseconds}ms")
    }

    @Test
    fun robinEntitlementPsshChallengeIsFast() = runTest {
        val owner = HostCdmOwner(Cdm.fromDevice(loadDevice()))
        val s = owner.open()
        val t = measureTime {
            val ch = s.challenge(java.util.Base64.getDecoder().decode(robinPssh))
            assertTrue(ch.isNotEmpty())
        }
        println("ROBIN_CHALLENGE_MS=${t.inWholeMilliseconds}")
        owner.release(s)
        assertTrue(t.inWholeMilliseconds < 10_000, "robin entitlement pssh challenge took ${t.inWholeMilliseconds}ms")
    }
}
