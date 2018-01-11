package net.corda.nodeapi.internal.serialization.amqp

import net.corda.core.utilities.contextLogger
import net.corda.core.utilities.debug
import net.corda.core.utilities.trace
import net.corda.nodeapi.internal.serialization.amqp.SerializerFactory.Companion.nameForType
import org.apache.qpid.proton.amqp.Symbol
import org.apache.qpid.proton.codec.Data
import java.io.NotSerializableException
import java.lang.reflect.Type
import kotlin.reflect.jvm.javaConstructor

/**
 * Responsible for serializing and deserializing a regular object instance via a series of properties
 * (matched with a constructor).
 */
open class ObjectSerializer(val clazz: Type, factory: SerializerFactory) : AMQPSerializer<Any> {
    override val type: Type get() = clazz
    open val kotlinConstructor = constructorForDeserialization(clazz)
    val javaConstructor by lazy { kotlinConstructor?.javaConstructor }

    companion object {
        private val logger = contextLogger()
    }

    open internal val propertySerializers: List<PropertyAccessor> by lazy {
        propertiesForSerialization(kotlinConstructor, clazz, factory)
    }

    fun getPropertySerializers() = propertySerializers

    private val typeName = nameForType(clazz)

    override val typeDescriptor = Symbol.valueOf("$DESCRIPTOR_DOMAIN:${fingerprintForType(type, factory)}")

    // We restrict to only those annotated or whitelisted
    private val interfaces = interfacesForSerialization(clazz, factory)

    open internal val typeNotation: TypeNotation by lazy {
        CompositeType(typeName, null, generateProvides(), Descriptor(typeDescriptor), generateFields())
    }

    override fun writeClassInfo(output: SerializationOutput) {
        if (output.writeTypeNotations(typeNotation)) {
            for (iface in interfaces) {
                output.requireSerializer(iface)
            }

            propertySerializers.forEach { property ->
                property.getter.writeClassInfo(output)
            }
        }
    }

    override fun writeObject(obj: Any, data: Data, type: Type, output: SerializationOutput) = ifThrowsAppend({ clazz.typeName }) {
        // Write described
        data.withDescribed(typeNotation.descriptor) {
            // Write list
            withList {
                propertySerializers.forEach { property ->
                    property.getter.writeProperty(obj, this, output)
                }
            }
        }
    }

    override fun readObject(
            obj: Any,
            schemas: SerializationSchemas,
            input: DeserializationInput): Any = ifThrowsAppend({ clazz.typeName }) {
        if (obj is List<*>) {
            if (obj.size > propertySerializers.size) {
                throw NotSerializableException("Too many properties in described type $typeName")
            }

            when (propertySerializers.first()) {
                is PropertyAccessor.ProperAccessorGetterSetter ->
                    readObjectBuildViaSetters(obj, schemas, input)
                is PropertyAccessor.ProperAccessorConstructor ->
                    readObjectBuildViaConstructor(obj, schemas, input)
            }
        } else throw NotSerializableException("Body of described type is unexpected $obj")
    }

    private fun readObjectBuildViaConstructor(
            obj: List<*>,
            schemas: SerializationSchemas,
            input: DeserializationInput) : Any = ifThrowsAppend({ clazz.typeName }){
        logger.trace { "Calling construction based construction for ${clazz.typeName}" }

        return construct(obj.zip(propertySerializers).map { it.second.getter.readProperty(it.first, schemas, input) })
    }

    private fun readObjectBuildViaSetters(
            obj: List<*>,
            schemas: SerializationSchemas,
            input: DeserializationInput) : Any = ifThrowsAppend({ clazz.typeName }){
        logger.trace { "Calling setter based construction for ${clazz.typeName}" }

        val instance : Any = javaConstructor?.newInstance() ?: throw NotSerializableException (
                "Failed to instantiate instance of object $clazz")

        // read the properties out of the serialised form
        val propertiesFromBlob = obj
                .zip(propertySerializers)
                .map { it.second.getter.readProperty(it.first, schemas, input) }

        // one by one take a property and invoke the setter on the class
        propertySerializers.zip(propertiesFromBlob).forEach {
            it.first.set(instance, it.second)
        }

        return instance
    }

    private fun generateFields(): List<Field> {
        return propertySerializers.map {
            Field(it.getter.name, it.getter.type, it.getter.requires, it.getter.default, null, it.getter.mandatory, false)
        }
    }

    private fun generateProvides(): List<String> = interfaces.map { nameForType(it) }

    fun construct(properties: List<Any?>): Any {
        logger.trace { "Calling constructor: '$javaConstructor' with properties '$properties'" }

        return javaConstructor?.newInstance(*properties.toTypedArray()) ?:
                throw NotSerializableException("Attempt to deserialize an interface: $clazz. Serialized form is invalid.")
    }
}