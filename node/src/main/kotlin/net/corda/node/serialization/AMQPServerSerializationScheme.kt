package net.corda.node.serialization

import net.corda.core.serialization.SerializationContext
import net.corda.core.utilities.ByteSequence
import net.corda.nodeapi.internal.serialization.amqp.AbstractAMQPSerializationScheme
import net.corda.nodeapi.internal.serialization.amqp.SerializerFactory

class AMQPServerSerializationScheme : AbstractAMQPSerializationScheme() {
    override fun rpcClientSerializerFactory(context: SerializationContext) = SerializerFactory(context.whitelist, context.deserializationClassLoader)

    override fun rpcServerSerializerFactory(context: SerializationContext) =
            SerializerFactory(context.whitelist, context.deserializationClassLoader)

    override fun canDeserializeVersion(byteSequence: ByteSequence, target: SerializationContext.UseCase) =
        canDeserializeVersion(byteSequence) && (target != SerializationContext.UseCase.Checkpoint)
}

