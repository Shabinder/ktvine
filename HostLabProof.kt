import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.host.HostCdmSession
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseType
import java.nio.file.Files
import java.nio.file.Path
import java.net.URI
import java.net.HttpURLConnection

fun main(args: Array<String>) = runBlocking {
    val device = Device.loads(Files.readAllBytes(Path.of(args[0])))
    println("DEVICE_LOADED type=" + device.type + " securityLevel=" + device.securityLevel)
    val xml = Files.readString(Path.of(args[1]))
    val init = Regex("<cenc:pssh[^>]*>([^<]+)</cenc:pssh>").find(xml)!!.groupValues[1].trim()
    val cdm = Cdm.fromDevice(device)
    val session = HostCdmSession.open(cdm)
    try {
        val challenge = session.challenge(java.util.Base64.getDecoder().decode(init))
        println("CHALLENGE_OK bytes=" + challenge.size)
        val conn = URI("https://proxy.uat.widevine.com/proxy?video_id=2015_tears&provider=widevine_test").toURL().openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.connectTimeout = 15000
        conn.readTimeout = 30000
        conn.setRequestProperty("Content-Type", "application/octet-stream")
        conn.outputStream.use { it.write(challenge) }
        val code = conn.responseCode
        println("LICENSE_HTTP status=" + code)
        check(code == 200) { "License endpoint rejected request; status=$code" }
        val response = conn.inputStream.use { it.readBytes() }
        session.installLicense(response)
        check(session.isLicensed())
        println("HOST_LICENSE_VERIFIED keysRemainInBackend=true")
        println("LAB_KTVINE_PROOF_OK")
    } finally {
        session.close(); session.close(); check(runCatching { session.isLicensed() }.isFailure)
        println("SESSION_CLOSED")
    }
}
