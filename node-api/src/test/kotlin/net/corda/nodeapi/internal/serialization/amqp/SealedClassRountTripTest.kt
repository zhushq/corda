package net.corda.nodeapi.internal.serialization.amqp

import org.junit.Test
import java.io.File

import net.corda.core.serialization.SerializedBytes
import net.corda.core.utilities.ByteSequence

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

        println (sf.classCarpenter.loaded)

        val sc2 = f.readBytes()
        val deserializedC = DeserializationInput(sf).deserialize(SerializedBytes<Any>(sc2))
//        val deserializedC2 = DeserializationInput(sf).deserialize(ByteSequence (sc2 , Derived2::class.java)

        println (sf.classCarpenter.loaded)

        println (deserializedC::class.java)
    }
}