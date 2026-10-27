# SoundBound host integration

Fork base: Samfun75/ktvine fe5ff0a883d20362b7a2b434fcb6bfb473baea63.
Apache-2.0 attribution remains intact.

HostCdmSession is a common Kotlin adapter: host-created backend, opaque license
challenge/response, bounded inputs, serialized operations, readiness without key export,
and idempotent close. It is not a security sandbox: the underlying Cdm API retains key
access. Dropping session ownership does not guarantee cryptographic zeroization.

Provider orchestration and HTTP belong in the extension; credentials and software-CDM
sessions belong in the host. No credentials, keys or licenses are bundled here.
HostLabProof.kt is an isolated JVM public-test runner accepting a local authorized WVD
path and public Tears of Steel MPD path. It verifies license installation and lifecycle
without printing keys. It is not wired into Gradle or SoundBound production.

Linux ARM64 JVM live exchange passed. The adapter and owner suite has six passing
Gradle JVM tests with JDK21. No other platform is runtime-validated.
The Android AAR also builds successfully, and Android host tests pass all six adapter/owner
cases plus the six upstream CryptoProviderTest cases. These tests execute on the host JVM;
they do not establish Android ART, device crypto, live licensing or playback.
Follow-up certbox instrumentation passes fourteen tests on ART: six adapter/owner, six
crypto-vector and two Android provider checks. Gradle built the test APK but its SDK adb
launcher failed; system adb installed it and ran the selected classes directly. This
establishes tested device crypto/lifecycle behavior, not live licensing or app playback.

HostCdmOwner owns the sessions of one capability instance. It serializes open/shutdown,
rejects opens after shutdown starts, removes explicitly released sessions and attempts
all remaining closes even if one fails. Failed closes remain tracked for retry. Shutdown
and explicit release run in NonCancellable so caller cancellation does not interrupt
cleanup. Backend credential lifetime/storage is separate; no credentials are copied.
HostCdmSession now revokes all further operations when close attempts backend cleanup,
including after a failed close, while permitting cleanup retry. A regression against
the previous implementation fails because isLicensed still returns true; the patched
adapter suite passes seven cases and the full hermetic JVM suite passes 174 tests.
The final Android test APK also passes all 15 selected tests on certbox ART:
seven session/owner cases, six crypto vectors and two Android provider checks.
The final live host binding/media harness passes, and independent Bento4/FFmpeg
verification matches full PCM, three seek windows, HTTP/downloader/shared-guest files.
Upstream supports JVM, Android, iOS and linuxX64. There is no JS/QuickJS, Linux ARM64
Native, macOS Native or Windows Native target. Desktop JVM does not require MediaDrm,
a browser or the Android HAL. Native-image builds need separate validation.

Next: actual Zipline host-session binding and returned-service lifecycle; host-held key
references into the generic media executor; authorized full-media correctness and seek
proof; Android/iOS and desktop platform runs; credential import/storage and capability
advertisement; signed OTA and queue/downloader integration. None of those are shipped
by this initial adapter. Service acceptance is established only for the public endpoint.

The adapter now offers a host-only withContentKey callback for trusted media executors.
It requires an open licensed session, resolves a matching key, and clears its temporary
copy on success or exception. Never bind it into a guest service. It cannot prevent a
trusted callback retaining the bytes and does not guarantee zeroization of backend keys.
The SoundBound harness uses it with the production CENC implementation on the public
Tears of Steel audio: full EOF PCM and three seek windows match independent Bento4.
The real QuickJS host-session binding and five-session cleanup proof also pass; shipping
player/downloader integration and other platform runs remain outstanding.
