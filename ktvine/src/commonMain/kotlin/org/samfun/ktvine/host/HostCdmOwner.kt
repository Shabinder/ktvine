package org.samfun.ktvine.host

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.samfun.ktvine.cdm.CdmApi

/** Owns the sessions of one host capability instance, even when its backend is shared. */
public class HostCdmOwner(private val cdm: CdmApi) {
    private val lock: Mutex = Mutex()
    private val sessions: MutableSet<HostCdmSession> = mutableSetOf()
    private var closed: Boolean = false

    /** Serialize session creation with shutdown so an opened session cannot escape ownership. */
    public suspend fun open(): HostCdmSession = lock.withLock {
        check(!closed) { "CDM owner is closed" }
        HostCdmSession.open(cdm).also { sessions.add(it) }
    }

    /** Release an owned session; a failed backend close remains owned for shutdown retry. */
    public suspend fun release(session: HostCdmSession): Unit = withContext(NonCancellable) {
        lock.withLock {
            if (session in sessions) {
                session.close()
                sessions.remove(session)
            }
        }
    }

    /**
     * Reject future opens immediately and attempt every owned close, including after cancellation.
     * Failed closes remain owned: callers may retry shutdown. Successful closes are not repeated.
     */
    public suspend fun close(): Unit = withContext(NonCancellable) {
        lock.withLock {
            closed = true
            var failure: Throwable? = null
            for (session in sessions.toList()) {
                try {
                    session.close()
                    sessions.remove(session)
                } catch (closeFailure: Throwable) {
                    val previous = failure
                    if (previous == null) failure = closeFailure
                    else if (previous !== closeFailure) previous.addSuppressed(closeFailure)
                }
            }
            failure?.let { throw it }
        }
    }
}
