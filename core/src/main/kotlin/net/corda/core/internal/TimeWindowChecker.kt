package net.corda.core.internal

import net.corda.core.contracts.TimeWindow
import java.time.Clock
import java.time.Instant

/**
 * Checks if the current instant provided by the input clock falls within the provided time-window.
 */
class TimeWindowChecker(val clock: Clock = Clock.systemUTC()) {
    /** Checks if the current time is within the given [timeWindow], throws [OutOfBoundsException] if not. */
    fun validate(timeWindow: TimeWindow) {
        val currentTime = clock.instant()
        if (currentTime !in timeWindow) throw OutOfBoundsException(currentTime, timeWindow)
    }

    class OutOfBoundsException(val currentTime: Instant, val timeWindow: TimeWindow) : Exception() {
        override fun toString() = "Current time $currentTime is outside the time bounds specified by the transaction: $timeWindow"
    }
}
