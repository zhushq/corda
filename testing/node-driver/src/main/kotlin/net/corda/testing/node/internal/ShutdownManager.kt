package net.corda.testing.node.internal

import net.corda.core.concurrent.CordaFuture
import net.corda.core.internal.ThreadBox
import net.corda.core.internal.concurrent.doneFuture
import net.corda.core.utilities.Try
import net.corda.core.utilities.contextLogger
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.seconds
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

class ShutdownManager(private val executorService: ExecutorService) {
    private class State {
        val registeredShutdowns = ArrayList<CordaFuture<() -> Unit>>()
        var isShutdown = false
    }

    private val state = ThreadBox(State())

    companion object {
        private val log = contextLogger()
        inline fun <A> run(providedExecutorService: ExecutorService? = null, block: ShutdownManager.() -> A): A {
            val executorService = providedExecutorService ?: Executors.newScheduledThreadPool(1)
            val shutdownManager = ShutdownManager(executorService)
            try {
                return block(shutdownManager)
            } finally {
                shutdownManager.shutdown()
                providedExecutorService ?: executorService.shutdown()
            }
        }
    }

    fun shutdown() {
        log.info("shutting down!")
        val shutdownActionFutures = state.locked {
            if (isShutdown) {
                emptyList<CordaFuture<() -> Unit>>()
            } else {
                isShutdown = true
                log.info("Shutdownmanager futures are ${registeredShutdowns.joinToString()}")
                registeredShutdowns
            }
        }

        val shutdowns = shutdownActionFutures.map {
            log.info("Getting shutdown action future $it")
            Try.on {
                it.getOrThrow(1.seconds)
            }
        }
        shutdowns.reversed().forEach {
            when (it) {
                is Try.Success ->

                    try {
                        it.value()
                        log.info("successfully invoked shutdown: ${it.value}")
                    } catch (t: Throwable) {
                        log.warn("Exception while shutting down", t)
                    }
                is Try.Failure -> {
                    log.warn("Exception while getting shutdown method, disregarding", it.exception)
                }
            }
        }
        log.info("Shutdown done, shutdowns: ${shutdowns.count()}")
    }

    fun registerShutdown(shutdown: CordaFuture<() -> Unit>) {
        log.info("Attepting to register shutdown: $shutdown")
        state.locked {
            require(!isShutdown)
            log.info("Registering shutdown: $shutdown")
            registeredShutdowns += shutdown
        }
    }

    fun registerShutdown(shutdown: () -> Unit) = registerShutdown(doneFuture(shutdown))

    fun registerProcessShutdown(process: Process) {
        registerShutdown {
            process.destroy()
            /** Wait 5 seconds, then [Process.destroyForcibly] */
            val finishedFuture = executorService.submit {
                process.waitFor()
            }
            try {
                finishedFuture.getOrThrow(5.seconds)
            } catch (timeout: TimeoutException) {
                finishedFuture.cancel(true)
                process.destroyForcibly()
            }
        }
    }

    interface Follower {
        fun unfollow()
        fun shutdown()
    }

    fun follower() = object : Follower {
        private val start = state.locked { registeredShutdowns.size }
        private val end = AtomicInteger(start - 1)
        override fun unfollow() = end.set(state.locked { registeredShutdowns.size })
        override fun shutdown() = end.get().let { end ->
            start > end && throw IllegalStateException("You haven't called unfollow.")
            state.locked {
                registeredShutdowns.subList(start, end).listIterator(end - start).run {
                    while (hasPrevious()) {
                        previous().getOrThrow().invoke()
                        set(doneFuture {}) // Don't break other followers by doing a remove.
                    }
                }
            }
        }
    }
}