package eu.mycellium.android

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidIdentityStoreTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val identityFile get() = context.noBackupFilesDir.resolve("identity.v1")
    private val store get() = AndroidIdentityStore(context)

    @Before
    @After
    fun removeIdentityFile() {
        identityFile.delete()
    }

    @Test
    fun identityRoundTripsEncryptedInsideNoBackupStorage() {
        val secret = ByteArray(64) { index -> (index * 17 + 3).toByte() }
        assertNull(store.load())

        store.save(secret)

        assertArrayEquals(secret, store.load())
        val stored = identityFile.readBytes()
        assertFalse(stored.asList().windowed(secret.size).any { it == secret.asList() })
        assertFalse(
            context.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0,
        )
    }

    @Test
    fun invalidIdentityLengthsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { store.save(ByteArray(63)) }
        assertThrows(IllegalArgumentException::class.java) { store.save(ByteArray(65)) }
        assertFalse(identityFile.exists())
    }

    @Test
    fun tamperedCiphertextFailsAuthentication() {
        store.save(ByteArray(64) { 7 })
        val tampered = identityFile.readBytes()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
        identityFile.writeBytes(tampered)

        assertThrows(Exception::class.java) { store.load() }
    }
}
