package net.corda.nodeapi.config

import net.corda.core.copyTo
import net.corda.core.createDirectories
import net.corda.core.crypto.KeyStoreUtilities
import net.corda.core.crypto.X509Utilities
import net.corda.core.div
import net.corda.core.exists
import org.bouncycastle.asn1.x500.X500Name
import java.nio.file.Path

interface SSLConfiguration {
    val keyStorePassword: String
    val trustStorePassword: String
    val certificatesDirectory: Path
    val sslKeystore: Path get() = certificatesDirectory / "sslkeystore.jks"
    val nodeKeystore: Path get() = certificatesDirectory / "nodekeystore.jks"
    val trustStoreFile: Path get() = certificatesDirectory / "truststore.jks"
}

interface NodeSSLConfiguration : SSLConfiguration {
    val baseDirectory: Path
    override val certificatesDirectory: Path get() = baseDirectory / "certificates"
}

/**
 * Strictly for dev only automatically construct a server certificate/private key signed from
 * the CA certs in Node resources. Then provision KeyStores into certificates folder under node path.
 */
fun SSLConfiguration.configureDevKeyAndTrustStores(legalName: X500Name) {
    certificatesDirectory.createDirectories()
    if (!trustStoreFile.exists()) {
        javaClass.classLoader.getResourceAsStream("net/corda/node/internal/certificates/cordatruststore.jks").copyTo(trustStoreFile)
    }

    if (!sslKeystore.exists() || !nodeKeystore.exists()) {
        val stream = javaClass.classLoader.getResourceAsStream("net/corda/node/internal/certificates/cordadevcakeys.jks")
        val caKeyStore = KeyStoreUtilities.loadKeyStore(stream, "cordacadevpass")
        X509Utilities.createKeystoreForCordaNode(
                sslKeystore,
                nodeKeystore,
                keyStorePassword,
                keyStorePassword,
                caKeyStore,
                "cordacadevkeypass",
                legalName)
    }
}