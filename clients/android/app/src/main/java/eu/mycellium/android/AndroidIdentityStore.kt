package eu.mycellium.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Stores the opaque Rust identity under a non-exportable Android Keystore key. */
class AndroidIdentityStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "identity.v1"))

    fun load(): ByteArray? {
        if (!file.baseFile.exists()) return null
        val blob = file.readFully()
        require(blob.size > 13) { "secure identity is corrupt" }
        val ivLength = blob[0].toInt() and 0xff
        require(ivLength in 12..16 && blob.size > 1 + ivLength) {
            "secure identity is corrupt"
        }
        val iv = blob.copyOfRange(1, 1 + ivLength)
        val ciphertext = blob.copyOfRange(1 + ivLength, blob.size)
        return Cipher.getInstance(TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(128, iv))
            doFinal(ciphertext)
        }
    }

    fun save(secret: ByteArray) {
        require(secret.size == 64) { "identity has an invalid size" }
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, wrappingKey())
        }
        val ciphertext = cipher.doFinal(secret)
        val blob = byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + ciphertext
        val stream = file.startWrite()
        try {
            stream.write(blob)
            stream.fd.sync()
            file.finishWrite(stream)
        } catch (error: Throwable) {
            file.failWrite(stream)
            throw error
        }
    }

    private fun wrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let {
            return it.secretKey
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                generator.init(builder.setIsStrongBoxBacked(true).build())
                return generator.generateKey()
            } catch (_: StrongBoxUnavailableException) {
                builder.setIsStrongBoxBacked(false)
            } catch (_: Throwable) {
                builder.setIsStrongBoxBacked(false)
            }
        }
        generator.init(builder.build())
        return generator.generateKey()
    }

    private companion object {
        const val KEY_ALIAS = "eu.mycellium.identity.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
