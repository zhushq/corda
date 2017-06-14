package net.corda.node.services.config

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import net.corda.core.div
import net.corda.nodeapi.config.configOf
import java.nio.file.Path

object ConfigHelper {
    fun loadConfig(baseDirectory: Path,
                   configFile: Path = baseDirectory / "node.conf",
                   allowMissingConfig: Boolean = false,
                   configOverrides: Config = ConfigFactory.empty()): Config {
        val parseOptions = ConfigParseOptions.defaults()
        val defaultConfig = ConfigFactory.parseResources("reference.conf", parseOptions.setAllowMissing(false))
        val appConfig = ConfigFactory.parseFile(configFile.toFile(), parseOptions.setAllowMissing(allowMissingConfig))
        return configOf(
                // Add substitution values here
                "basedir" to baseDirectory.toString())
                .withFallback(configOverrides)
                .withFallback(appConfig)
                .withFallback(defaultConfig)
                .resolve()
    }
}