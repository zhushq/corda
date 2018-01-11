package net.corda.nodeapi.internal.serialization.amqp

import org.junit.Test

class SerializationPropertyOrdering {
    companion object {
        val VERBOSE get() = true
    }

    @Test
    fun reverseOrder() {
        data class C(val c: Int, val b: Int, val a: Int)

        val sf = testDefaultFactoryNoEvolution()

        TestSerializationOutput(VERBOSE, sf).serialize(C(30,20,10))
    }
}