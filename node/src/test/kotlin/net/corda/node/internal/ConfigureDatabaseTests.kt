package net.corda.node.internal

import net.corda.core.internal.concurrent.fork
import net.corda.core.internal.join
import net.corda.core.node.services.IdentityService
import net.corda.core.utilities.getOrThrow
import net.corda.nodeapi.internal.persistence.DatabaseConfig
import net.corda.testing.internal.rigorousMock
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.*
import java.util.concurrent.Executors

class ConfigureDatabaseTests {
    @Rule
    @JvmField
    val baseDirectory = TemporaryFolder()

    private fun newDataSourceProperties(nodeName: String) = Properties().apply {
        // TODO: A version of this test that uses reference.conf defaults.
        put("dataSourceClassName", "org.h2.jdbcx.JdbcDataSource")
        put("dataSource.url", "jdbc:h2:file:${baseDirectory.root}/$nodeName/persistence;DB_CLOSE_ON_EXIT=FALSE;LOCK_TIMEOUT=10000;WRITE_DELAY=100;AUTO_SERVER_PORT=0")
        put("dataSource.user", "sa")
        put("dataSource.password", "")
    }

    @Test
    fun `get it working`() {
        val dataSourcePropertiesList = listOf("Alice", "Bob").map(this::newDataSourceProperties)
        val databaseConfig = DatabaseConfig()
        val identityService = rigorousMock<IdentityService>()
        val pool = Executors.newScheduledThreadPool(2) // What driver does.
        val databases = dataSourcePropertiesList.map {
            pool.fork {
                configureDatabase(it, databaseConfig, identityService)
            }
        }
        databases.forEach {
            it.getOrThrow().close()
        }
        pool.join()
    }
}
