package net.corda.verifier

import com.google.common.net.HostAndPort
import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import net.corda.core.ErrorOr
import net.corda.core.div
import net.corda.core.utilities.debug
import net.corda.core.utilities.loggerFor
import net.corda.nodeapi.ArtemisTcpTransport.Companion.tcpTransport
import net.corda.nodeapi.ConnectionDirection
import net.corda.nodeapi.VerifierApi
import net.corda.nodeapi.VerifierApi.VERIFICATION_REQUESTS_QUEUE_NAME
import net.corda.nodeapi.config.SSLConfiguration
import net.corda.nodeapi.config.parseAs
import org.apache.activemq.artemis.api.core.client.ActiveMQClient
import java.nio.file.Path
import java.nio.file.Paths

data class VerifierConfiguration(val baseDirectory: Path,
                                 val nodeHostAndPort: HostAndPort,
                                 override val keyStorePassword: String,
                                 override val trustStorePassword: String) : SSLConfiguration {
    override val certificatesDirectory get() = baseDirectory / "certificates"
}

class Verifier {
    companion object {
        private val log = loggerFor<Verifier>()

        fun loadConfiguration(baseDirectory: Path, configPath: Path): VerifierConfiguration {
            val options = ConfigParseOptions.defaults().setAllowMissing(false)
            val defaultConfig = ConfigFactory.parseResources("verifier-reference.conf", options)
            val customConfig = ConfigFactory.parseFile(configPath.toFile(), options)
            val overrideConfig = ConfigFactory.parseMap(mapOf(
                    "baseDirectory" to baseDirectory.toString())
            )
            val resolvedConfig = overrideConfig.withFallback(customConfig).withFallback(defaultConfig).resolve()
            return resolvedConfig.parseAs<VerifierConfiguration>()
        }

        @JvmStatic
        fun main(args: Array<String>) {
            require(args.isNotEmpty()) { "Usage: <binary> BASE_DIR_CONTAINING_VERIFIER_CONF" }
            val baseDirectory = Paths.get(args[0])
            val verifierConfig = loadConfiguration(baseDirectory, baseDirectory / "verifier.conf")
            val locator = ActiveMQClient.createServerLocatorWithHA(
                    tcpTransport(ConnectionDirection.Outbound(), verifierConfig.nodeHostAndPort, verifierConfig)
            )
            val sessionFactory = locator.createSessionFactory()
            val session = sessionFactory.createSession(
                    VerifierApi.VERIFIER_USERNAME, VerifierApi.VERIFIER_USERNAME, false, true, true, locator.isPreAcknowledge, locator.ackBatchSize
            )
            Runtime.getRuntime().addShutdownHook(Thread {
                log.info("Shutting down")
                session.close()
                sessionFactory.close()
            })
            val consumer = session.createConsumer(VERIFICATION_REQUESTS_QUEUE_NAME)
            val replyProducer = session.createProducer()
            consumer.setMessageHandler {
                val request = VerifierApi.VerificationRequest.fromClientMessage(it)
                log.debug { "Received verification request with id ${request.verificationId}" }
                val result = ErrorOr.catch {
                    request.transaction.verify()
                }
                if (result.error != null) {
                    log.debug { "Verification returned with error ${result.error}" }
                }
                val reply = session.createMessage(false)
                val response = VerifierApi.VerificationResponse(request.verificationId, result.error)
                response.writeToClientMessage(reply)
                replyProducer.send(request.responseAddress, reply)
                it.acknowledge()
            }
            session.start()
            log.info("Verifier started")
            Thread.sleep(Long.MAX_VALUE)
        }
    }
}