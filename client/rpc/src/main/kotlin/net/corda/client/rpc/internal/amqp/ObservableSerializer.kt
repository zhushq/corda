package net.corda.client.rpc.internal.amqp

import net.corda.nodeapi.internal.serialization.amqp.*
import org.apache.qpid.proton.codec.Data
import rx.Observable
import java.lang.reflect.Type
import java.time.*

/**
 */
object ObservableSerializer : CustomSerializer.Implements<Observable<*>>(Observable::class.java) {
    override val schemaForDocumentation = Schema(listOf(RestrictedType(
            type.toString(),
            "",
            listOf(type.toString()),
            SerializerFactory.primitiveTypeName()!!,
            descriptor,
            emptyList())))

    override fun writeDescribedObject(obj: Observable<*>, data: Data, type: Type, output: SerializationOutput) {
        throw java.io.NotSerializableException("POOP 1")
    }

    override fun readObject(obj: Any, schema: Schema, input: DeserializationInput): Observable<*> {
        throw java.io.NotSerializableException("POOP 2")
    }

}
