package net.corda.nodeapi.internal.serialization.amqp

import org.junit.Test
import java.io.File

import net.corda.core.serialization.SerializedBytes

//
sealed class SealedBaseA
data class Derived1(val a: Integer) : SealedBaseA()
data class Derived2(val b: Integer) : SealedBaseA()
//
// Remove  Derived three as that's what was serialised for serialisedIsRemovedType
//
//data class Derived3(val c: Integer) : SealedBaseA()

class SealedClassRoundTripTest {
    @Test
    fun serialiasedIsRemovedType() {
        val path = EvolvabilityTests::class.java.getResource("SealedClassRoundTripTests.serialisedIsRemovedType")
        val sf = testDefaultFactory()
        val f = File(path.toURI())

        //
        //
        // val sc = SerializationOutput(sf).serialize(Derived3(Integer(3)))
        // f.writeBytes(sc.bytes)
        // println(path)


        val sc2 = f.readBytes()
        val deserializedC = DeserializationInput(sf).deserialize(SerializedBytes<Object>(sc2))
        println (deserializedC::class.java)
    }

}