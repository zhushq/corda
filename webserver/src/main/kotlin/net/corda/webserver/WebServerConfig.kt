package net.corda.webserver

import com.google.common.net.HostAndPort
import net.corda.core.div
import net.corda.nodeapi.config.SSLConfiguration
import java.nio.file.Path

/**
 * [baseDirectory] is not retrieved from the config file but rather from a command line argument.
 */
data class WebServerConfig(
        val baseDirectory: Path,
        override val keyStorePassword: String,
        override val trustStorePassword: String,
        val useHTTPS: Boolean,
        // TODO: Use RPC port instead of P2P port (RPC requires authentication, P2P does not)
        val p2pAddress: HostAndPort,
        val webAddress: HostAndPort) : SSLConfiguration {
    override val certificatesDirectory: Path get() = baseDirectory / "certificates"
    val exportJMXto: String get() = "http"
}