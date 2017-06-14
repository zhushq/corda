package net.corda.webserver

import com.google.common.net.HostAndPort
import net.corda.nodeapi.config.NodeSSLConfiguration
import java.nio.file.Path

data class WebServerConfig(
        val basedir: Path,
        override val keyStorePassword: String,
        override val trustStorePassword: String,
        val useHTTPS: Boolean,
        val myLegalName: String,
        // TODO: Use RPC port instead of P2P port (RPC requires authentication, P2P does not)
        val p2pAddress: HostAndPort,
        val webAddress: HostAndPort
) : NodeSSLConfiguration {
    /** This is not retrieved from the config file but rather from a command line argument. */
    override val baseDirectory: Path get() = basedir
    val exportJMXto: String get() = "http"
}
