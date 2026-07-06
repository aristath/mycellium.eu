package eu.mycellium.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.mycellium_sdk.DeliveryState
import uniffi.mycellium_sdk.Message
import uniffi.mycellium_sdk.MyceliumClient
import java.io.File

/**
 * On-device end-to-end test: exercises the REAL native stack — the UniFFI Kotlin
 * binding → JNA → the Rust `libmycellium_sdk.so` → HTTP → a live directory+queue
 * on the host → X3DH decrypt — plus the hardware-backed [AndroidKeystoreSecretStore].
 *
 * This is the layer a host-only (JVM) test cannot reach: it only passes if the
 * `.so` loads on Android, the JNA signatures match, the Keystore adapter works on
 * the device, and the SDK's `ureq` HTTP actually talks to the servers from inside
 * the app sandbox (cleartext-to-10.0.2.2 allowed by the network-security config).
 *
 * The directory + queue run on the host; the emulator reaches them at 10.0.2.2.
 * Ports come from instrumentation args (`-Pandroid.testInstrumentationRunnerArguments.dirPort=...`),
 * defaulting to 18080/18090. The directory must run with MYCELLIUM_DEV_AUTH=1 so
 * `startEmailVerification` echoes the code.
 */
@RunWith(AndroidJUnit4::class)
class MessagingE2eTest {

    private val args = InstrumentationRegistry.getArguments()
    private val host = args.getString("host", "10.0.2.2")
    private val dir = "http://$host:${args.getString("dirPort", "18080")}"
    private val queue = "http://$host:${args.getString("queuePort", "18090")}"

    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext

    private fun freshClient(name: String): MyceliumClient {
        val dataDir = File(ctx.filesDir, "e2e-$name").apply { deleteRecursively(); mkdirs() }
        // A namespaced Keystore store so two in-process accounts don't collide on
        // the "identity" secret (the reason the adapter takes a namespace).
        return MyceliumClient.newWithSecretStore(
            dataDir.path,
            AndroidKeystoreSecretStore(ctx, "e2e-$name"),
        )
    }

    /** Real onboarding: email-verify (dev code) then publish the record. */
    private fun onboard(client: MyceliumClient, handle: String) {
        val verification = client.startEmailVerification(dir, handle, "$handle@example.test")
        val code = verification.devCode
            ?: error("directory did not echo a dev code — is MYCELLIUM_DEV_AUTH=1 set?")
        client.confirmEmailVerification(dir, verification.pending, code)
        client.register(dir, queue, handle, handle.replaceFirstChar { it.uppercase() })
    }

    @Test
    fun full_messaging_round_trip_on_device() {
        val alice = freshClient("alice")
        val bob = freshClient("bob")

        onboard(alice, "alicedroid")
        onboard(bob, "bobdroid")

        val text = "hello from a real android device"
        val sent = alice.sendText("bobdroid", text)
        assertNotEquals("send should not fail outright", DeliveryState.FAILED, sent.delivery)

        // Bob drains his queue and decrypts (poll briefly for delivery).
        var received: List<Message> = emptyList()
        for (attempt in 0 until 15) {
            received = bob.sync()
            if (received.any { it.text == text }) break
            Thread.sleep(300)
        }
        assertTrue(
            "bob should receive + decrypt the message; got ${received.map { it.text }}",
            received.any { it.text == text },
        )

        // And it lands in bob's transcript with alice.
        val thread = bob.thread("alicedroid")
        assertTrue(
            "the message should be in bob's thread with alice",
            thread.any { it.text == text && !it.fromMe },
        )
    }

    /**
     * A multi-step GROUP flow over the real native stack (mirrors the desktop
     * `group_round_trip`): alice creates a group with bob; bob `sync()`s to process
     * the `GroupInvite` and join (learning the SAME group id from the invite);
     * alice sends to the group; bob receives it in his group thread on a later
     * `sync()`. Non-vacuous — a group message is actually sealed, delivered, and
     * decrypted between two in-process clients through the live directory+queue.
     */
    @Test
    fun group_round_trip_on_device() {
        val alice = freshClient("alice")
        val bob = freshClient("bob")

        onboard(alice, "alicedroid")
        onboard(bob, "bobdroid")

        // Alice creates the group with bob; the SDK seals her group sender-key to
        // bob as a GroupInvite deposited on his queue.
        val gid = alice.groupCreate("g", listOf("bobdroid"))
        assertTrue(
            "alice's own group list should contain the new group",
            alice.groups().any { it.id == gid },
        )

        // Bob must sync() to process the invite and join. He learns the group (and
        // its shared id) from the invite; poll a few ticks for eventual delivery.
        var joined = false
        for (attempt in 0 until 40) {
            bob.sync()
            if (bob.groups().any { it.id == gid }) {
                joined = true
                break
            }
            Thread.sleep(100)
        }
        assertTrue("bob never joined the group via the invite", joined)

        // Bob's group id matches alice's (both refer to the same group), with name.
        val bobGroup = bob.groups().first { it.id == gid }
        val bobGid = bobGroup.id
        assertEquals("bob learned the group name from the invite", "g", bobGroup.name)

        // Alice sends a message to the group; bob receives it in the group thread.
        val text = "hi group from a real android device"
        alice.groupSend(gid, text)

        var delivered = false
        for (attempt in 0 until 40) {
            bob.sync()
            if (bob.groupThread(bobGid).any { it.text == text }) {
                delivered = true
                break
            }
            Thread.sleep(100)
        }
        assertTrue("bob never received alice's group message via sync", delivered)

        // And it lands in bob's group transcript, attributed to alice.
        val thread = bob.groupThread(bobGid)
        assertTrue(
            "group message should be in bob's group thread, attributed to alice; " +
                "got ${thread.map { it.sender to it.text }}",
            thread.any { it.text == text && !it.fromMe && it.sender == "alicedroid" },
        )
    }

    @Test
    fun keystore_identity_persists_across_reopen() {
        val dataDir = File(ctx.filesDir, "e2e-persist").apply { deleteRecursively(); mkdirs() }

        val first = MyceliumClient.newWithSecretStore(
            dataDir.path, AndroidKeystoreSecretStore(ctx, "e2e-persist"),
        )
        val wallet = first.walletAddress()
        assertTrue("a wallet address should be derived", wallet.isNotEmpty())
        first.close()

        // Reopen: the identity secret must load back through the Keystore-sealed
        // blob and reproduce the same account — proving the adapter round-trips
        // on a real device, not just in a JVM mock.
        val second = MyceliumClient.newWithSecretStore(
            dataDir.path, AndroidKeystoreSecretStore(ctx, "e2e-persist"),
        )
        assertEquals(
            "Keystore-backed identity must persist across reopen",
            wallet,
            second.walletAddress(),
        )
        second.close()
    }
}
