package net.corda.core.transactions

import net.corda.core.contracts.*
import net.corda.core.crypto.*
import net.corda.core.identity.Party
import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.SerializedBytes
import net.corda.core.serialization.deserialize
import net.corda.core.serialization.serialize
import net.corda.core.utilities.OpaqueBytes
import java.security.PublicKey
import java.util.function.Predicate

/**
 * Implemented by [WireTransaction] and [FilteredLeaves]. A TraversableTransaction allows you to iterate
 * over the flattened components of the underlying transaction structure, taking into account that some
 * may be missing in the case of this representing a "torn" transaction. Please see the user guide section
 * "Transaction tear-offs" to learn more about this feature.
 *
 * The [availableComponents] property is used for calculation of the transaction's [MerkleTree], which is in
 * turn used to derive the ID hash.
 */
interface TraversableTransaction {
    val inputs: List<StateRef>
    val attachments: List<SecureHash>
    val outputs: List<TransactionState<ContractState>>
    val commands: List<Command<*>>
    val notary: Party?
    val timeWindow: TimeWindow?
    /**
     * For privacy purposes, each part of a transaction should be accompanied by a nonce.
     * To avoid storing a random number (nonce) per component, an initial "salt" is the sole value utilised,
     * so that all component nonces are deterministically computed in the following way:
     * nonce1 = H(salt || 1)
     * nonce2 = H(salt || 2)
     *
     * Thus, all of the nonces are "independent" in the sense that knowing one or some of them, you can learn
     * nothing about the rest.
     */
    val privacySalt: PrivacySalt?

    /**
     * Returns a list of all the component groups that are present in the transaction, excluding the privacySalt,
     * in the following order (which is the same with the order in [ComponentGroupEnum]:
     * - list of each input that is present
     * - list of each output that is present
     * - list of each command that is present
     * - list of each attachment that is present
     * - The notary [Party], if present (list with one element)
     * - The time-window of the transaction, if present (list with one element)
    */
    val availableComponentGroups: List<List<Any>>
        get() {
            val result = mutableListOf(inputs, outputs, commands, attachments)
            notary?.let { result += listOf(it) }
            timeWindow?.let { result += listOf(it) }
            return result
        }

    /** Calculate the nonces of the sub-components of the transaction. */
    val availableComponentNonces: List<List<SecureHash>>
        get() = availableComponentGroups.mapIndexed { index, it -> it.mapIndexed {
            indexInternal, itInternal -> serializedHash(itInternal, privacySalt, index, indexInternal) }
        }

    /**
     * Calculate the hashes of the sub-components of the transaction, that are used to build its Merkle tree.
     * The root of the tree is the transaction identifier. The tree structure is helpful for privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    val availableComponentHashes: List<List<SecureHash>>
        get() = availableComponentGroups.mapIndexed { index, it -> it.mapIndexed {
            indexInternal, itInternal -> serializedHash(itInternal, availableComponentNonces[index][indexInternal]) }
        }
}

/**
 * Class that holds filtered leaves for a partial Merkle transaction. We assume mixed leaf types, notice that every
 * field from [WireTransaction] can be used in [PartialMerkleTree] calculation, except for the privacySalt.
 * A list of nonces is also required to (re)construct component hashes.
 */
@CordaSerializable
class FilteredLeaves(
        override val inputs: List<StateRef>,
        override val attachments: List<SecureHash>,
        override val outputs: List<TransactionState<ContractState>>,
        override val commands: List<Command<*>>,
        override val notary: Party?,
        override val timeWindow: TimeWindow?
) : TraversableTransaction {

    /**
     * PrivacySalt should be always null for FilteredLeaves, because making it accidentally visible would expose all
     * nonces (including filtered out components) causing privacy issues, see [serializedHash] and
     * [TraversableTransaction.privacySalt].
     */
    override val privacySalt: PrivacySalt? get() = null

    init {
        // require(availableComponents.size == nonces.size) { "Each visible component should be accompanied by a nonce." }
    }

    /**
     * Function that checks the whole filtered structure.
     * Force type checking on a structure that we obtained, so we don't sign more than expected.
     * Example: Oracle is implemented to check only for commands, if it gets an attachment and doesn't expect it - it can sign
     * over a transaction with the attachment that wasn't verified. Of course it depends on how you implement it, but else -> false
     * should solve a problem with possible later extensions to WireTransaction.
     * @param checkingFun function that performs type checking on the structure fields and provides verification logic accordingly.
     * @returns false if no elements were matched on a structure or checkingFun returned false.
     */
    fun checkWithFun(checkingFun: (Any) -> Boolean): Boolean {
        val checkList = availableComponentGroups.flatten().map { checkingFun(it) }
        return (!checkList.isEmpty()) && checkList.all { it }
    }

    // override val availableComponentHashes: List<SecureHash> get() = availableComponents.mapIndexed { index, it -> serializedHash(it, nonces[index]) }
}

/**
 * Class representing merkleized filtered transaction.
 * @param id Merkle tree root hash.
 * @param filteredLeaves Leaves included in a filtered transaction.
 * @param partialMerkleTree Merkle branch needed to verify filteredLeaves.
 */
@CordaSerializable
class FilteredTransaction private constructor(
        val id: SecureHash,
        val filteredComponentGroups: List<FilteredComponentGroup>,
        private val partialMerkleTree: PartialMerkleTree
) {

    val filteredLeaves: FilteredLeaves = buildFilteredLeaves()

    private fun buildFilteredLeaves(): FilteredLeaves {
        try {
            /** Pointers to the input states on the ledger, identified by (tx identity hash, output index). */
            val inputs: List<StateRef> = filteredComponentGroups[ComponentGroupEnum.INPUTS_GROUP.ordinal].components.map { SerializedBytes<StateRef>(it.bytes).deserialize() }

            val outputs: List<TransactionState<ContractState>> = filteredComponentGroups[ComponentGroupEnum.OUTPUTS_GROUP.ordinal].components.map { SerializedBytes<TransactionState<ContractState>>(it.bytes).deserialize() }

            /** Ordered list of ([CommandData], [PublicKey]) pairs that instruct the contracts what to do. */
            val commands: List<Command<*>> = filteredComponentGroups[ComponentGroupEnum.COMMANDS_GROUP.ordinal].components.map { SerializedBytes<Command<*>>(it.bytes).deserialize() }

            /** Hashes of the ZIP/JAR files that are needed to interpret the contents of this wire transaction. */
            val attachments: List<SecureHash> = filteredComponentGroups[ComponentGroupEnum.ATTACHMENTS_GROUP.ordinal].components.map { SerializedBytes<SecureHash>(it.bytes).deserialize() }

            val notary: Party? = buildNotary()

            val timeWindow: TimeWindow? = buildTimeWindow()

            return FilteredLeaves(inputs, attachments, outputs, commands, notary, timeWindow)
        } catch (cce: ClassCastException) {
            throw ClassCastException("Malformed FilteredTransaction, one of the components cannot be deserialised - ${cce.message}")
        }
    }

    private fun buildNotary(): Party? {
        val notaries: List<Party> = filteredComponentGroups[ComponentGroupEnum.NOTARY_GROUP.ordinal].components.map { SerializedBytes<Party>(it.bytes).deserialize() }
        check(notaries.size <= 1) { "Invalid Transaction. More than 1 notary party detected." }
        return if (notaries.isNotEmpty()) notaries[0] else null
    }

    private fun buildTimeWindow(): TimeWindow? {
        val timeWindows: List<TimeWindow> = filteredComponentGroups[ComponentGroupEnum.TIMEWINDOW_GROUP.ordinal].components.map { SerializedBytes<TimeWindow>(it.bytes).deserialize() }
        check(timeWindows.size <= 1) { "Invalid Transaction. More than 1 time-window detected." }
        return if (timeWindows.isNotEmpty()) timeWindows[0] else null
    }

    companion object {
        /**
         * Construction of filtered transaction with partial Merkle tree.
         * @param wtx WireTransaction to be filtered.
         * @param filtering filtering over the whole WireTransaction
         */
        @JvmStatic
        fun buildFilteredTransaction(wtx: WireTransaction,
                                     filtering: Predicate<Any>
        ): FilteredTransaction {
            val filteredComponentGroups = filterWithFun(wtx, filtering)
            val merkleTree = wtx.merkleTree
            val groupHashes = filteredComponentGroups.mapIndexed { index, it -> wtx.groupsMerkleRoots[index] }.filterIndexed { index, it -> filteredComponentGroups[index].components.isNotEmpty() }
            val pmt = PartialMerkleTree.build(merkleTree, groupHashes)
            return FilteredTransaction(merkleTree.hash, filteredComponentGroups, pmt)
        }

        /**
         * Construction of partial transaction from [WireTransaction] based on filtering.
         * Note that list of nonces to be sent is updated on the fly, based on the index of the filtered tx component.
         * @param filtering filtering over the whole WireTransaction
         * @returns FilteredLeaves used in PartialMerkleTree calculation and verification.
         */
        private fun filterWithFun(wtx: WireTransaction, filtering: Predicate<Any>): List<FilteredComponentGroup> {

            val filteredSerialisedComponents: MutableMap<Int, MutableList<OpaqueBytes>> = hashMapOf()
            val filteredComponentNonces: MutableMap<Int, MutableList<SecureHash>> = hashMapOf()
            val filteredComponentHashes: MutableMap<Int, MutableList<SecureHash>> = hashMapOf() // Required for partial Merkle tree generation.

            fun <T : Any> filter(t: T, index: Int, ordinal: Int) {
                if (filtering.test(t)) {
                    val group = filteredSerialisedComponents[ordinal]
                    if (group == null) {
                        filteredSerialisedComponents.put(ordinal, mutableListOf(t.serialize()))
                        filteredComponentNonces.put(ordinal, mutableListOf(wtx.availableComponentNonces[ordinal][index]))
                        filteredComponentHashes.put(ordinal, mutableListOf(wtx.availableComponentHashes[ordinal][index]))
                    } else {
                        group.add(t.serialize())
                        filteredComponentNonces[ordinal]!!.add(wtx.availableComponentNonces[ordinal][index])
                        filteredComponentHashes[ordinal]!!.add(wtx.availableComponentHashes[ordinal][index])
                    }
                }
            }

            fun updateFilteredComponents() {
                wtx.inputs.forEachIndexed { index, it -> filter(it, index, ComponentGroupEnum.INPUTS_GROUP.ordinal) }
                wtx.outputs.forEachIndexed { index, it -> filter(it, index, ComponentGroupEnum.OUTPUTS_GROUP.ordinal) }
                wtx.commands.forEachIndexed { index, it -> filter(it, index, ComponentGroupEnum.COMMANDS_GROUP.ordinal) }
                wtx.attachments.forEachIndexed { index, it -> filter(it, index, ComponentGroupEnum.ATTACHMENTS_GROUP.ordinal) }
                if (wtx.notary != null) filter(wtx.notary!!, 0, ComponentGroupEnum.NOTARY_GROUP.ordinal)
                if (wtx.timeWindow != null) filter(wtx.timeWindow!!, 0, ComponentGroupEnum.TIMEWINDOW_GROUP.ordinal)
            }

            fun createPartialMerkleTree(ordinal: Int) = PartialMerkleTree.build(MerkleTree.getMerkleTree(wtx.availableComponentHashes[ordinal]), filteredComponentHashes[ordinal]!!)

            fun createFilteredComponentGroups(): List<FilteredComponentGroup> {
                updateFilteredComponents()
                val filteredComponentGroups: MutableList<FilteredComponentGroup> = mutableListOf()
                for (ordinal in 0 until ComponentGroupEnum.values().size) {
                    val group = filteredSerialisedComponents[ordinal]
                    if (group != null) {
                        filteredComponentGroups.add(FilteredComponentGroup(group, filteredComponentNonces[ordinal]!!, createPartialMerkleTree(ordinal) ))
                    } else {
                        filteredComponentGroups.add(FilteredComponentGroup()) // Add an empty group.
                    }
                }
                return filteredComponentGroups
            }

            // TODO: We should have a warning (require) if all leaves (excluding salt) are visible after filtering.
            //      Consider the above after refactoring FilteredTransaction to implement TraversableTransaction,
            //      so that a WireTransaction can be used when required to send a full tx (e.g. RatesFixFlow in Oracles).
            return createFilteredComponentGroups()
        }
    }

    /**
     * Runs verification of partial Merkle branch against [id].
     */
    @Throws(MerkleTreeException::class)
    fun verify(): Boolean {
        val hashes: List<SecureHash> = filteredComponentGroups.map { it.nonces }.flatten()
        if (hashes.isEmpty())
            throw MerkleTreeException("Transaction without included leaves.")
        val groupHashes = filteredComponentGroups.filter { it.partialMerkleTree != null }.map { it.partialMerkleTree!!.verify(it.partialMerkleTree.root, mutableListOf()) }
        return partialMerkleTree.verify(id, groupHashes)
    }
}

/**
 * A FilteredComponentGroup is used to store the filtered list of transaction components of the same type in serialised form.
 * This is similar to [ComponentGroup], but it also includes the corresponding nonce per component.
 */
@CordaSerializable
data class FilteredComponentGroup(val components: List<OpaqueBytes>, val nonces: List<SecureHash>, val partialMerkleTree: PartialMerkleTree?) {

    /** A helper constructor to create empty filtered component groups. */
    constructor() : this(emptyList(), emptyList(), null)

    init {
        check(components.size == nonces.size) { "Size of components and nonces does not match" }
    }
}
