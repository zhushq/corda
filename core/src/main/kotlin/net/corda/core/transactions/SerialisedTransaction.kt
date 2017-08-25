package net.corda.core.transactions

import net.corda.core.contracts.PrivacySalt
import net.corda.core.crypto.MerkleTree
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.sha256
import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.SerializationDefaults
import net.corda.core.serialization.serialize
import net.corda.core.utilities.OpaqueBytes
import java.nio.ByteBuffer

@CordaSerializable
data class SerialisedTransaction(val componentGroups: List<ComponentGroup?>, val privacySalt: PrivacySalt) {

    /**
     * Builds whole Merkle tree for a transaction.
     */
    val merkleTree: MerkleTree by lazy { MerkleTree.getMerkleTree(groupsMerkleRoots) }

    /**
     * Calculate the hashes of the sub-components of the transaction, that are used to build its Merkle tree.
     * The root of the tree is the transaction identifier. The tree structure is helpful for privacy, please
     * see the user-guide section "Transaction tear-offs" to learn more about this topic.
     */
    val groupsMerkleRoots: List<SecureHash> get() = componentGroups.mapIndexed { index, it ->
        if (it != null) {
            serializedHash(
                    MerkleTree.getMerkleTree(it.components.mapIndexed { indexInternal, itInternal ->
                        serializedHash(itInternal, privacySalt, index, indexInternal) }),
                    privacySalt,
                    index
            )
        } else {
            serializedHash(SecureHash.zeroHash, privacySalt, index)
        }
    }

    /**
     * If a privacy salt is provided, the resulted output (Merkle-leaf) is computed as
     * Hash(serializedObject || Hash(privacy_salt || obj_index_in_merkle_tree)).
     */
    private fun <T : Any> serializedHash(x: T, privacySalt: PrivacySalt?, index: Int): SecureHash {
        return if (privacySalt != null)
            serializedHash(x, computeNonce(privacySalt, index))
        else
            serializedHash(x)
    }

    private fun <T : Any> serializedHash(x: T, privacySalt: PrivacySalt?, index: Int, indexInternal: Int): SecureHash {
        return if (privacySalt != null)
            serializedHash(x, computeNonce(privacySalt, index, indexInternal))
        else
            serializedHash(x)
    }

    private fun <T : Any> serializedHash(x: T, nonce: SecureHash): SecureHash {
        return if (x !is PrivacySalt) // PrivacySalt is not required to have an accompanied nonce.
            (x.serialize(context = SerializationDefaults.P2P_CONTEXT.withoutReferences()).bytes + nonce.bytes).sha256()
        else
            serializedHash(x)
    }

    private fun <T : Any> serializedHash(x: T): SecureHash = x.serialize(context = SerializationDefaults.P2P_CONTEXT.withoutReferences()).bytes.sha256()

    /** The nonce is computed as Hash(privacySalt || index). */
    private fun computeNonce(privacySalt: PrivacySalt, index: Int) = (privacySalt.bytes + ByteBuffer.allocate(4).putInt(index).array()).sha256()

    /** The nonce is computed as Hash(privacySalt || index || indexInternal). */
    private fun computeNonce(privacySalt: PrivacySalt, index: Int, indexInternal: Int) = (privacySalt.bytes + ByteBuffer.allocate(4).putInt(index).array() + ByteBuffer.allocate(4).putInt(indexInternal).array()).sha256()
}

/**
 * A ComponentGroup is used to store the full list of transaction components of the same type in serialised form.
 * Practically, a group per component type of a transaction is required; thus, there will be a group for input states,
 * a group for all attachments (if there are any) etc.
 */
@CordaSerializable
data class ComponentGroup(val components: List<OpaqueBytes>)