package net.corda.core.internal

import net.corda.core.contracts.TimeWindow
import net.corda.core.utilities.seconds
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertFailsWith

class TimeWindowCheckerTests {
    val clock: Clock = Clock.fixed(Instant.now(), ZoneOffset.UTC)
    val timeWindowChecker = TimeWindowChecker(clock)

    @Test
    fun `should return true for valid time-window`() {
        val now = clock.instant()
        val timeWindowBetween = TimeWindow.between(now - 10.seconds, now + 10.seconds)
        val timeWindowFromOnly = TimeWindow.fromOnly(now - 10.seconds)
        val timeWindowUntilOnly = TimeWindow.untilOnly(now + 10.seconds)

        timeWindowChecker.validate(timeWindowBetween)
        timeWindowChecker.validate(timeWindowFromOnly)
        timeWindowChecker.validate(timeWindowUntilOnly)
    }

    @Test
    fun `should return false for invalid time-window`() {
        val now = clock.instant()
        val timeWindowBetweenPast = TimeWindow.between(now - 10.seconds, now - 2.seconds)
        val timeWindowBetweenFuture = TimeWindow.between(now + 2.seconds, now + 10.seconds)
        val timeWindowFromOnlyFuture = TimeWindow.fromOnly(now + 10.seconds)
        val timeWindowUntilOnlyPast = TimeWindow.untilOnly(now - 10.seconds)

        assertFailsWith<TimeWindowChecker.OutOfBoundsException> { timeWindowChecker.validate(timeWindowBetweenPast) }
        assertFailsWith<TimeWindowChecker.OutOfBoundsException> { timeWindowChecker.validate(timeWindowBetweenFuture) }
        assertFailsWith<TimeWindowChecker.OutOfBoundsException> { timeWindowChecker.validate(timeWindowFromOnlyFuture) }
        assertFailsWith<TimeWindowChecker.OutOfBoundsException> { timeWindowChecker.validate(timeWindowUntilOnlyPast) }
    }
}
