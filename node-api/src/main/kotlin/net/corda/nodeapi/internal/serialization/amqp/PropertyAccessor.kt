package net.corda.nodeapi.internal.serialization.amqp

import net.corda.core.utilities.loggerFor
import java.io.NotSerializableException
import java.lang.reflect.Method
import java.lang.reflect.Type
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.javaGetter
import kotlin.reflect.jvm.kotlinProperty
import java.lang.reflect.Field

abstract class PropertyReader {
    abstract fun read(obj: Any?): Any?
    abstract fun isNullable(): Boolean
}

class PublicPropertyReader(private val readMethod: Method?) : PropertyReader() {
    init {
        readMethod?.isAccessible = true
    }

    private fun Method.returnsNullable(): Boolean {
        try {
            val returnTypeString = this.declaringClass.kotlin.memberProperties.firstOrNull {
                it.javaGetter == this
            }?.returnType?.toString() ?: "?"

            return returnTypeString.endsWith('?') || returnTypeString.endsWith('!')
        } catch (e: kotlin.reflect.jvm.internal.KotlinReflectionInternalError) {
            // This might happen for some types, e.g. kotlin.Throwable? - the root cause of the issue
            // is: https://youtrack.jetbrains.com/issue/KT-13077
            // TODO: Revisit this when Kotlin issue is fixed.

            loggerFor<PropertySerializer>().error("Unexpected internal Kotlin error", e)
            return true
        }
    }

    override fun read(obj: Any?): Any? {
        return readMethod!!.invoke(obj)
    }

    override fun isNullable(): Boolean = readMethod?.returnsNullable() ?: false
}

class PrivatePropertyReader(val field: Field, parentType: Type) : PropertyReader() {
    init {
        loggerFor<PropertySerializer>().warn("Create property Serializer for private property '${field.name}' not "
                + "exposed by a getter on class '$parentType'\n"
                + "\tNOTE: This behaviour will be deprecated at some point in the future and a getter required")
    }

    override fun read(obj: Any?): Any? {
        field.isAccessible = true
        val rtn = field.get(obj)
        field.isAccessible = false
        return rtn
    }

    override fun isNullable() = try {
        field.kotlinProperty?.returnType?.isMarkedNullable ?: false
    } catch (e: kotlin.reflect.jvm.internal.KotlinReflectionInternalError) {
        // This might happen for some types, e.g. kotlin.Throwable? - the root cause of the issue
        // is: https://youtrack.jetbrains.com/issue/KT-13077
        // TODO: Revisit this when Kotlin issue is fixed.
        loggerFor<PropertySerializer>().error("Unexpected internal Kotlin error", e)
        true
    }
}

/**
 *
 */
sealed class PropertyAccessor(open val getter: PropertySerializer) {
    companion object : Comparator<PropertyAccessor> {
        override fun compare(p0: PropertyAccessor?, p1: PropertyAccessor?): Int {
            return p0?.getter?.name?.compareTo(p1?.getter?.name ?: "") ?: 0
        }
    }

   abstract fun set(instance: Any, obj: Any?)

    override fun toString(): String {
        return getter.name
    }

    class ProperAccessorGetterSetter(
            override val getter: PropertySerializer,
            private val setter: Method?) : PropertyAccessor(getter) {
        override fun set(instance: Any, obj: Any?) {
            setter?.invoke(instance, *listOf(obj).toTypedArray())
        }
    }

    class ProperAccessorConstructor(
            val oPosition: Int,
            override val getter: PropertySerializer) : PropertyAccessor(getter) {
        override fun set(instance: Any, obj: Any?) {
            NotSerializableException ("Attempting to access a setter on an object being instantiated " +
                    "via its constructor.")
        }
    }
}

