package org.samfun.ktvine

import org.samfun.ktvine.core.Device
import java.io.File
import kotlin.test.Test

/**
 * Phase 1a of the export-to-raw validation. Hermetic (no network): parses every WVD in the pool
 * directory via the real [Device.loads] and reports type/level buckets. Prints ONLY counts — never
 * key bytes, client ids, or device identifiers. Skips cleanly when the pool dir is not supplied.
 *
 * Run: `-Dwvd.pool.dir=$HOME/.config/soundbound/wvd` with the jvmTest task.
 */
class DevicePoolJvmTest {
    @Test
    fun `parse every device in the research pool`() {
        val dir = System.getProperty("wvd.pool.dir")?.let(::File)
        if (dir == null || !dir.isDirectory) {
            println("SKIP: set -Dwvd.pool.dir to the gitignored WVD store to run Phase 1a.")
            return
        }
        val files = dir.listFiles { f -> f.extension == "wvd" }?.sortedBy { it.name } ?: emptyList()
        var ok = 0
        var bad = 0
        val byType = sortedMapOf<String, Int>()
        val byLevel = sortedMapOf<Int, Int>()
        val failCauses = linkedMapOf<String, Int>()
        for (f in files) {
            try {
                val d = Device.loads(f.readBytes())
                require(d.privateKeyDer.isNotEmpty()) { "empty private key" }
                ok++
                byType.merge(d.type.name, 1, Int::plus)
                byLevel.merge(d.securityLevel, 1, Int::plus)
            } catch (e: Throwable) {
                bad++
                failCauses.merge((e.message ?: e::class.simpleName ?: "unknown").take(60), 1, Int::plus)
            }
        }
        println("POOL_TOTAL=${files.size} PARSE_OK=$ok PARSE_FAIL=$bad")
        println("BY_TYPE=$byType BY_LEVEL=$byLevel")
        if (failCauses.isNotEmpty()) println("FAIL_CAUSES=$failCauses")
        check(files.isNotEmpty()) { "pool dir had no .wvd files" }
        check(bad == 0) { "some devices failed to parse: $failCauses" }
        println("PHASE_1A_OK")
    }
}
