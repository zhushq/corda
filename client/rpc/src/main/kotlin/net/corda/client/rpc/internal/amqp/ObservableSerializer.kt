package net.corda.client.rpc.internal.amqp

import net.corda.client.rpc.internal.ObservableContext
import net.corda.core.serialization.SerializationContext
import net.corda.nodeapi.RPCApi
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
            Observable::class.java.name,
            descriptor,
            emptyList())))

    override fun writeDescribedObject(obj: Observable<*>, data: Data, type: Type, output: SerializationOutput) {
        throw java.io.NotSerializableException("POOP 1")
    }

    override fun readObject(obj: Any, schema: Schema, input: DeserializationInput): Observable<*> {
    //    if (true) {
            throw java.io.NotSerializableException("POOP 2")
      //  }

//        val observableContext = context[RpcObservableContextKey] as ObservableContext

        /*
        val observableId = RPCApi.ObservableId(input.readLong(true))
        val observable = UnicastSubject.create<Notification<*>>()
        require(observableContext.observableMap.getIfPresent(observableId) == null) {
            "Multiple Observables arrived with the same ID $observableId"
        }
        val rpcCallSite = getRpcCallSite(kryo, observableContext)
        observableContext.observableMap.put(observableId, observable)
        observableContext.callSiteMap?.put(observableId.toLong, rpcCallSite)
        // We pin all Observables into a hard reference store (rooted in the RPC proxy) on subscription so that users
        // don't need to store a reference to the Observables themselves.
        return pinInSubscriptions(observable, observableContext.hardReferenceStore).doOnUnsubscribe {
            // This causes Future completions to give warnings because the corresponding OnComplete sent from the server
            // will arrive after the client unsubscribes from the observable and consequently invalidates the mapping.
            // The unsubscribe is due to [ObservableToFuture]'s use of first().
            observableContext.observableMap.invalidate(observableId)
        }.dematerialize()
        */
    }

/*
    private fun <T> pinInSubscriptions(observable: Observable<T>, hardReferenceStore: MutableSet<Observable<*>>): Observable<T> {
        val refCount = AtomicInteger(0)
        return observable.doOnSubscribe {
            if (refCount.getAndIncrement() == 0) {
                require(hardReferenceStore.add(observable)) { "Reference store already contained reference $this on add" }
            }
        }.doOnUnsubscribe {
            if (refCount.decrementAndGet() == 0) {
                require(hardReferenceStore.remove(observable)) { "Reference store did not contain reference $this on remove" }
            }
        }
    }

    private fun getRpcCallSite(kryo: Kryo, observableContext: ObservableContext): Throwable? {
        val rpcRequestOrObservableId = kryo.context[RPCApi.RpcRequestOrObservableIdKey] as Long
        return observableContext.callSiteMap?.get(rpcRequestOrObservableId)
    }
    */
}
