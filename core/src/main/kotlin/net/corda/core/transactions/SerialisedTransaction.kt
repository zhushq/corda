package net.corda.core.transactions

import com.google.common.annotations.VisibleForTesting
import net.corda.core.contracts.PrivacySalt
import net.corda.core.crypto.MerkleTree
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.serializedHash
import net.corda.core.crypto.sha256
import net.corda.core.serialization.CordaSerializable
import net.corda.core.utilities.OpaqueBytes

@CordaSerializable
data class SerialisedTransaction(val componentGroups: List<ComponentGroup>, val privacySalt: PrivacySalt) {

    /**
     * Builds whole Merkle tree for a transaction.
     */
    val merkleTree: MerkleTree by lazy { MerkleTree.getMerkleTree(listOf(privacySalt.sha256()) + groupsMerkleRoots) }

    /**
     * Calculate the hashes of the sub-components of the transaction, that are used to build its Merkle tree.
     * The root of the tree is the transaction identifier. The tree structure is helpful for privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    @VisibleForTesting
    val groupsMerkleRoots: List<SecureHash> get() = componentGroups.mapIndexed { index, it ->
        if (it.components.isNotEmpty()) {
            MerkleTree.getMerkleTree(it.components.mapIndexed { indexInternal, itInternal ->
                serializedHash(itInternal, privacySalt, index, indexInternal) }).hash
        } else {
            SecureHash.zeroHash
        }
    }
}

/**
 * A ComponentGroup is used to store the full list of transaction components of the same type in serialised form.
 * Practically, a group per component type of a transaction is required; thus, there will be a group for input states,
 * a group for all attachments (if there are any) etc.
 */
@CordaSerializable
data class ComponentGroup(val components: List<OpaqueBytes>)
