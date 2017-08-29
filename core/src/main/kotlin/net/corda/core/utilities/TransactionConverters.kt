@file:JvmName("TransactionConverters")
package net.corda.core.utilities

import net.corda.core.contracts.*
import net.corda.core.crypto.SecureHash
import net.corda.core.identity.Party
import net.corda.core.serialization.SerializedBytes
import net.corda.core.serialization.deserialize
import net.corda.core.serialization.serialize
import net.corda.core.transactions.ComponentGroup
import net.corda.core.transactions.SerialisedTransaction
import net.corda.core.transactions.WireTransaction

fun wirefromSerialised(serTransaction: SerialisedTransaction): WireTransaction {
    try {
        val inputs: List<StateRef> = serTransaction.componentGroups[0].components.map { SerializedBytes<StateRef>(it.bytes).deserialize() }
        val outputs: List<TransactionState<ContractState>> = serTransaction.componentGroups[1].components.map { SerializedBytes<TransactionState<ContractState>>(it.bytes).deserialize() }
        val commands: List<Command<*>> = serTransaction.componentGroups[2].components.map { SerializedBytes<Command<*>>(it.bytes).deserialize() }
        val attachments: List<SecureHash> = serTransaction.componentGroups[3].components.map { SerializedBytes<SecureHash>(it.bytes).deserialize() }
        val notaries: List<Party> = serTransaction.componentGroups[4].components.map { SerializedBytes<Party>(it.bytes).deserialize() }
        val timeWindows: List<TimeWindow> = serTransaction.componentGroups[5].components.map { SerializedBytes<TimeWindow>(it.bytes).deserialize() }
        require(notaries.size <= 1) { "Invalid Transaction. More than 1 notary party detected." }
        require(timeWindows.size <= 1) { "Invalid Transaction. More than 1 time-window detected." }
        return WireTransaction(
                inputs,
                attachments,
                outputs,
                commands,
                if (notaries.isNotEmpty()) notaries[0] else null,
                if (timeWindows.isNotEmpty()) timeWindows[0] else null,
                serTransaction.privacySalt
        )
    } catch (cce: ClassCastException) {
        throw ClassCastException("Wire transaction cannot be serialised: ${cce.message}")
    }
}

fun wireToSerialised(wireTransaction: WireTransaction): SerialisedTransaction {
    val inputs = ComponentGroup(wireTransaction.inputs.map { it.serialize() })
    val outputs = ComponentGroup(wireTransaction.outputs.map { it.serialize() })
    val commands = ComponentGroup(wireTransaction.commands.map { it.serialize() })
    val attachments = ComponentGroup(wireTransaction.attachments.map { it.serialize() })
    val notaries = ComponentGroup(if (wireTransaction.notary != null) listOf(wireTransaction.notary.serialize()) else emptyList())
    val timeWindows = ComponentGroup(if (wireTransaction.timeWindow != null) listOf(wireTransaction.timeWindow.serialize()) else emptyList())
    return SerialisedTransaction(listOf(inputs, outputs, commands, attachments, notaries, timeWindows), wireTransaction.privacySalt)
}
