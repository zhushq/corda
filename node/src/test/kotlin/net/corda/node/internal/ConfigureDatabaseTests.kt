package net.corda.node.internal

import net.corda.core.node.services.IdentityService
import net.corda.nodeapi.internal.persistence.DatabaseConfig
import net.corda.testing.internal.rigorousMock
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.*

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
        // THEORY:
        // hikari does a fail fast thing on create data source. this makes an h2 db and closes it
        // we immediately do 2 transactions: one in CordaPersistence and another in AN
        // one of the tx causes H2 to spin in Engine. this blocks the other thread as a side-effect
        // so i believe we need 1 thread to make a hikari ds and spam a bunch of tx
        // then h2 should spin for 30s in Engine
        val dataSourceProperties = newDataSourceProperties("Alice")
        val databaseConfig = DatabaseConfig()
        val identityService = rigorousMock<IdentityService>()
        val database = configureDatabase(dataSourceProperties, databaseConfig, identityService)
        repeat(100) { // actually 10 is enough to break it, as pool size is 10 and confDat does a tx
            database.transaction {
                println("Connected to ${connection.metaData.databaseProductName} database.")
            }
        }
    }
}
