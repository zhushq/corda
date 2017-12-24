package net.corda.nodeapi.internal.crypto

import net.corda.core.crypto.Crypto
import net.corda.core.internal.uncheckedCast
import java.io.InputStream
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * Wrapper around a [KeyStore] object but only dealing with [X509Certificate]s and with a better API.
 */
class X509KeyStore private constructor(val internal: KeyStore, private val storePassword: String, private val keyStoreFile: Path?) {
    companion object {
        /**
         * Load an [X509KeyStore] from the given input, using the given store password. The returned key store cannot
         * be written to so [save] is unsupported.
         */
        fun fromStream(input: InputStream, storePassword: String): X509KeyStore {
            return X509KeyStore(loadKeyStore(input, storePassword), storePassword, null)
        }

        fun fromFile(keyStoreFile: Path, storePassword: String, createNew: Boolean = false): X509KeyStore {
            val internal: KeyStore = if (createNew) loadOrCreateKeyStore(keyStoreFile, storePassword) else loadKeyStore(keyStoreFile, storePassword)
            return X509KeyStore(internal, storePassword, keyStoreFile)
        }
    }

    fun containsAlias(alias: String): Boolean = internal.containsAlias(alias)

    fun aliases(): Iterator<String> = internal.aliases().iterator()

    fun deleteEntry(alias: String) {
        internal.deleteEntry(alias)
    }

    fun getCertificate(alias: String): X509Certificate = internal.getX509Certificate(alias)

    fun getCertificateChain(alias: String): List<X509Certificate> {
        val certArray = requireNotNull(internal.getCertificateChain(alias)) { "No certificate chain under the alias $alias" }
        check(certArray.all { it is X509Certificate }) { "Certificate chain under alias $alias is not X.509" }
        return uncheckedCast(certArray.asList())
    }

    fun getCertificateAndKeyPair(alias: String, keyPassword: String = storePassword): CertAndKeyPair {
        val cert = getCertificate(alias)
        val publicKey = Crypto.toSupportedPublicKey(cert.publicKey)
        return CertAndKeyPair(cert, KeyPair(publicKey, getPrivateKey(alias, keyPassword)))
    }

    fun getPrivateKey(alias: String, keyPassword: String = storePassword): PrivateKey {
        return internal.getSupportedKey(alias, keyPassword)
    }

    fun setPrivateKey(alias: String, key: PrivateKey, certificates: List<X509Certificate>, keyPassword: String = storePassword) {
        checkWritableToFile()
        internal.setKeyEntry(alias, key, keyPassword.toCharArray(), certificates.toTypedArray())
    }

    fun setCertificate(alias: String, certificate: X509Certificate) {
        checkWritableToFile()
        internal.setCertificateEntry(alias, certificate)
    }

    fun save() {
        internal.save(checkWritableToFile(), storePassword)
    }

    fun update(action: X509KeyStore.() -> Unit) {
        checkWritableToFile()
        action(this)
        save()
    }

    private fun checkWritableToFile(): Path {
        return keyStoreFile ?: throw IllegalStateException("This key store cannot be written to")
    }
}

data class CertAndKeyPair(val certificate: X509Certificate, val keyPair: KeyPair)