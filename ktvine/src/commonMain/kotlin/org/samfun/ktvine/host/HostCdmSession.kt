package org.samfun.ktvine.host

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okio.ByteString
import org.samfun.ktvine.cdm.CdmApi
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.License
import kotlin.uuid.Uuid

/**
 * Host-owned software-CDM session driven by opaque challenge/response messages.
 *
 * The caller owns license HTTP transport. Device credentials and content keys stay with [CdmApi].
 * This adapter does not provision devices, decrypt media, or implement a platform's protected decoder.
 * One adapter owns exactly one session. Operations and shutdown are serialized; close is idempotent.
 */
public class HostCdmSession private constructor(
    private val cdm: CdmApi,
    private val sessionId: ByteString,
) {
    private val lock: Mutex = Mutex()
    private var closed: Boolean = false
    private var closing: Boolean = false
    private var licensed: Boolean = false

    public companion object {
        /** Open a session in a host-created backend. No credential bytes cross this API. */
        public suspend fun open(cdm: CdmApi): HostCdmSession = HostCdmSession(cdm, cdm.open())
    }

    /** Configure an optional service certificate. The backend validates its signature. */
    public suspend fun setServiceCertificate(certificate: String?): Unit = lock.withLock {
        checkOpen()
        cdm.setServiceCertificate(sessionId, certificate)
        Unit
    }

    /** Produce a streaming-license request from initialization data supplied by the extension. */
    public suspend fun challenge(initData: ByteArray): ByteArray = lock.withLock {
        checkOpen()
        require(initData.size in 1..MAX_MESSAGE_BYTES) { "Invalid initialization-data size" }
        cdm.getLicenseChallenge(sessionId, PSSH(initData))
    }

    /** Verify a license response and retain its keys only in the host backend. */
    public suspend fun installLicense(response: ByteArray): Unit = lock.withLock {
        checkOpen()
        licensed = false
        require(response.size in 1..MAX_MESSAGE_BYTES) { "Invalid license-response size" }
        cdm.parseLicense(sessionId, response)
        check(cdm.getKeys(sessionId, License.KeyContainer.KeyType.CONTENT).isNotEmpty()) {
            "License contains no content keys"
        }
        licensed = true
    }

    /** Report readiness without returning key bytes or backend session identifiers. */
    public suspend fun isLicensed(): Boolean = lock.withLock {
        checkOpen()
        licensed
    }

    /**
     * Supply a temporary content-key copy to a trusted host media executor.
     * Never bind this method into a guest-facing service. The session lock keeps
     * close/license replacement from racing the executor. The callback must not
     * reenter this session or retain the key; the temporary copy is cleared on exit.
     */
    public suspend fun <T> withContentKey(kid: Uuid, consume: (ByteArray) -> T): T = lock.withLock {
        checkOpen()
        check(licensed) { "CDM session is not licensed" }
        val key = cdm.getKeys(sessionId, License.KeyContainer.KeyType.CONTENT)
            .singleOrNull { it.kid == kid } ?: error("Content key is unavailable")
        val copy = key.key.copyOf()
        try {
            consume(copy)
        } finally {
            copy.fill(0)
        }
    }

    /** Release the owned session. A failed close can be retried; successful close is idempotent. */
    public suspend fun close(): Unit = lock.withLock {
        // Keep revocation after failure while retaining the ability to retry cleanup.
        closing = true
        if (!closed) {
            licensed = false
            cdm.close(sessionId)
            closed = true
        }
    }

    private fun checkOpen(): Unit = check(!closed && !closing) { "CDM session is closed" }
}

private const val MAX_MESSAGE_BYTES: Int = 1024 * 1024
