package org.samfun.ktvine

import kotlinx.coroutines.test.runTest
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.cdm.CdmApi
import org.samfun.ktvine.core.Key
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.host.HostCdmSession
import org.samfun.ktvine.host.HostCdmOwner
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.LicenseType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

class HostCdmSessionTest {
    @Test
    fun failedCloseRevokesSessionButAllowsCleanupRetry() = runTest {
        val backend = Backend().apply { accept = true }
        val session = HostCdmSession.open(backend)
        session.installLicense(byteArrayOf(1))
        backend.failClose = true
        assertFailsWith<IllegalStateException> { session.close() }
        assertFailsWith<IllegalStateException> { session.isLicensed() }
        assertFailsWith<IllegalStateException> { session.challenge(byteArrayOf(1)) }
        assertFailsWith<IllegalStateException> { session.installLicense(byteArrayOf(1)) }
        assertFailsWith<IllegalStateException> { session.setServiceCertificate(null) }
        assertFailsWith<IllegalStateException> { session.withContentKey(Uuid.NIL) { } }
        backend.failClose = false
        session.close()
        session.close()
        assertEquals(2, backend.closeAttempts)
        assertEquals(1, backend.closes)
    }

    @Test
    fun ownersReleaseOnlyTheirSessionsAndRejectOpenAfterClose() = runTest {
        val backend = Backend()
        val first = HostCdmOwner(backend)
        val second = HostCdmOwner(backend)
        val oldSession = first.open()
        val newSession = second.open()
        first.close()
        first.close()
        assertEquals(1, backend.closes)
        assertFailsWith<IllegalStateException> { oldSession.isLicensed() }
        assertFalse(newSession.isLicensed())
        assertFailsWith<IllegalStateException> { first.open() }
        second.release(newSession)
        second.release(newSession)
        second.close()
        assertEquals(2, backend.closes)
    }

    @Test
    fun ownerAttemptsEveryCloseAndRetriesFailures() = runTest {
        val backend = Backend()
        val owner = HostCdmOwner(backend)
        owner.open()
        owner.open()
        backend.failClose = true
        assertFailsWith<IllegalStateException> { owner.close() }
        assertEquals(2, backend.closeAttempts)
        assertFailsWith<IllegalStateException> { owner.open() }
        backend.failClose = false
        owner.close()
        owner.close()
        assertEquals(4, backend.closeAttempts)
        assertEquals(2, backend.closes)
    }

    @Test
    fun invalidReplacementRevokesReadinessAndKeyAccess() = runTest {
        val backend = Backend().apply { accept = true }
        val session = HostCdmSession.open(backend)
        for (invalid in listOf(byteArrayOf(), ByteArray(1024 * 1024 + 1))) {
            session.installLicense(byteArrayOf(1))
            assertTrue(session.isLicensed())
            assertFailsWith<IllegalArgumentException> { session.installLicense(invalid) }
            assertFalse(session.isLicensed())
            assertFailsWith<IllegalStateException> { session.withContentKey(Uuid.NIL) { } }
        }
        session.close()
    }

    @Test
    fun hostKeyConsumerRequiresLicenseAndClearsTemporaryCopy() = runTest {
        val backend = Backend()
        val session = HostCdmSession.open(backend)
        assertFailsWith<IllegalStateException> { session.withContentKey(Uuid.NIL) { } }
        backend.accept = true
        session.installLicense(byteArrayOf(1))
        var observed: ByteArray? = null
        val size = session.withContentKey(Uuid.NIL) { key ->
            observed = key
            assertEquals(1, key[0].toInt())
            key.size
        }
        assertEquals(16, size)
        assertTrue(observed!!.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            session.withContentKey(Uuid.NIL) { key -> observed = key; error("executor failed") }
        }
        assertTrue(observed!!.all { it == 0.toByte() })
        session.withContentKey(Uuid.NIL) { assertEquals(1, it[0].toInt()) }
        assertFailsWith<IllegalStateException> { session.withContentKey(Uuid.random()) { } }
        session.close()
        assertFailsWith<IllegalStateException> { session.withContentKey(Uuid.NIL) { } }
    }

    @Test
    fun lifecycleAndLicenseRejection() = runTest {
        val backend = Backend()
        val session = HostCdmSession.open(backend)
        assertFalse(session.isLicensed())
        assertFailsWith<IllegalStateException> { session.installLicense(byteArrayOf(1)) }
        assertFalse(session.isLicensed())
        backend.accept = true
        session.installLicense(byteArrayOf(1))
        assertTrue(session.isLicensed())
        backend.accept = false
        assertFailsWith<IllegalStateException> { session.installLicense(byteArrayOf(1)) }
        assertFalse(session.isLicensed())
        session.close()
        session.close()
        assertEquals(1, backend.closes)
        assertFailsWith<IllegalStateException> { session.isLicensed() }
        assertFailsWith<IllegalStateException> { session.challenge(byteArrayOf(1)) }
        assertFailsWith<IllegalStateException> { session.installLicense(byteArrayOf(1)) }
        assertFailsWith<IllegalStateException> { session.setServiceCertificate(null) }
    }

    @Test
    fun boundsAndCloseRetry() = runTest {
        val backend = Backend()
        val session = HostCdmSession.open(backend)
        assertFailsWith<IllegalArgumentException> { session.challenge(byteArrayOf()) }
        assertFailsWith<IllegalArgumentException> { session.installLicense(ByteArray(1024 * 1024 + 1)) }
        backend.failClose = true
        assertFailsWith<IllegalStateException> { session.close() }
        backend.failClose = false
        session.close()
        assertEquals(1, backend.closes)
    }

    private class Backend : CdmApi {
        var accept = false
        var failClose = false
        var closes = 0
        var closeAttempts = 0
        override suspend fun open() = byteArrayOf(1).toByteString()
        override suspend fun close(sessionId: ByteString) {
            closeAttempts++
            check(!failClose)
            closes++
        }
        override suspend fun setServiceCertificate(sessionId: ByteString, certificateBase64: String?): String? = null
        override suspend fun getServiceCertificateBase64(sessionId: ByteString): String? = null
        override suspend fun getLicenseChallenge(sessionId: ByteString, pssh: PSSH, licenseType: LicenseType, privacyMode: Boolean, requestType: LicenseRequest.RequestType) = byteArrayOf(1)
        override suspend fun parseLicense(sessionId: ByteString, licenseMessage: ByteArray) { check(accept) }
        override suspend fun getKeys(sessionId: ByteString, type: License.KeyContainer.KeyType?): List<Key> =
            if (accept) listOf(Key(License.KeyContainer.KeyType.CONTENT, Uuid.NIL, ByteArray(16) { 1 })) else emptyList()
    }
}
