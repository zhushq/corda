package net.corda.core.contracts

import net.corda.core.crypto.MerkleTree
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.sha256
import net.corda.core.serialization.serialize
import net.corda.core.transactions.ComponentGroup
import net.corda.core.transactions.CompatibleTransaction
import net.corda.testing.*
import net.corda.testing.contracts.DummyContract
import org.junit.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class WireTransactionTests {

    private val dummyOutState = TransactionState(DummyContract.SingleOwnerState(0, ALICE), DUMMY_NOTARY)
    private val stateRef1 = StateRef(SecureHash.randomSHA256(), 0)
    private val stateRef2 = StateRef(SecureHash.randomSHA256(), 1)
    private val stateRef3 = StateRef(SecureHash.randomSHA256(), 0)

    private val inputs = listOf(stateRef1, stateRef2, stateRef3) // 3 elements.
    private val outputs = listOf(dummyOutState, dummyOutState.copy(notary = BOB)) // 2 elements.
    private val commands = listOf(dummyCommand(DUMMY_KEY_1.public, DUMMY_KEY_2.public)) // 1 element.
    private val attachments = emptyList<SecureHash>() // Empty list.
    private val notary = DUMMY_NOTARY
    private val timeWindow = TimeWindow.fromOnly(Instant.now())
    private val privacySalt: PrivacySalt = PrivacySalt()

    @Test
    fun `Merkle root computations`() {
        withTestSerialization {
            val inputGroup = ComponentGroup(inputs.map { it -> it.serialize() })
            val outputGroup = ComponentGroup(outputs.map { it -> it.serialize() })
            val commandGroup = ComponentGroup(commands.map { it -> it.serialize() })
            val attachmentGroup = ComponentGroup(attachments.map { it -> it.serialize() }) // The list is empty.
            val notaryGroup = ComponentGroup(listOf(notary.serialize()))
            val timeWindowGroup = ComponentGroup(listOf(timeWindow.serialize()))

            val componentGroupsA = listOf(inputGroup, outputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)

            val compatibleTransaction1 = CompatibleTransaction(componentGroups = componentGroupsA, privacySalt = privacySalt)
            val compatibleTransaction2 = CompatibleTransaction(componentGroups = componentGroupsA, privacySalt = privacySalt)

            // Merkle tree computation is deterministic.
            assertEquals(compatibleTransaction1.merkleTree, compatibleTransaction2.merkleTree)

            // Full Merkle root is computed from the list of Merkle roots of each component group.
            assertEquals(compatibleTransaction1.merkleTree, MerkleTree.getMerkleTree(listOf(privacySalt.sha256()) + compatibleTransaction1.groupsMerkleRoots))

            val componentGroupsEmptyOutputs = listOf(inputGroup, ComponentGroup(emptyList()), commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
            val compatibleTransactionEmptyOutputs = CompatibleTransaction(componentGroups = componentGroupsEmptyOutputs, privacySalt = privacySalt)

            // Because outputs list is empty, it should be zeroHash.
            assertEquals(SecureHash.zeroHash, compatibleTransactionEmptyOutputs.groupsMerkleRoots[1])

            // TXs differ in outputStates.
            assertNotEquals(compatibleTransaction1.merkleTree, compatibleTransactionEmptyOutputs.merkleTree)

            val inputsShuffled = listOf(stateRef2, stateRef1, stateRef3)
            val inputShuffledGroup = ComponentGroup(inputsShuffled.map { it -> it.serialize() })
            val componentGroupsB = listOf(inputShuffledGroup, outputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
            val compatibleTransaction1ShuffledInputs = CompatibleTransaction(componentGroups = componentGroupsB, privacySalt = privacySalt)

            // Ordering inside a component group matters.
            assertNotEquals(compatibleTransaction1, compatibleTransaction1ShuffledInputs)
            assertNotEquals(compatibleTransaction1.merkleTree, compatibleTransaction1ShuffledInputs.merkleTree)
            // Inputs group Merkle root is not equal.
            assertNotEquals(compatibleTransaction1.groupsMerkleRoots[0], compatibleTransaction1ShuffledInputs.groupsMerkleRoots[0])
            // But outputs group Merkle leaf (and the rest) remained the same.
            assertEquals(compatibleTransaction1.groupsMerkleRoots[1], compatibleTransaction1ShuffledInputs.groupsMerkleRoots[1])
            assertEquals(compatibleTransaction1.groupsMerkleRoots[3], compatibleTransaction1ShuffledInputs.groupsMerkleRoots[3])

            val shuffledComponentGroupsA = listOf(outputGroup, inputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
            val compatibleTransaction1ShuffledGroups = CompatibleTransaction(componentGroups = shuffledComponentGroupsA, privacySalt = privacySalt)

            // Ordering in the group leafs matters. We should keep a standardised sequence for backwards/forwards compatibility.
            // For instance inputs should always be the first leaf, then outputs, the commands etc.
            assertNotEquals(compatibleTransaction1, compatibleTransaction1ShuffledGroups)
            assertNotEquals(compatibleTransaction1.merkleTree, compatibleTransaction1ShuffledGroups.merkleTree)
            // First leaf (Merkle root) is not equal.
            assertNotEquals(compatibleTransaction1.groupsMerkleRoots[0], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[0])
            // Second leaf (Merkle leaf) is not equal.
            assertNotEquals(compatibleTransaction1.groupsMerkleRoots[1], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[1])
            // Actually, because the index participate in nonces, swapping group-leafs changes the Merkle roots.
            assertNotEquals(compatibleTransaction1.groupsMerkleRoots[0], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[1])
            assertNotEquals(compatibleTransaction1.groupsMerkleRoots[1], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[0])
            // However third leaf (and the rest) didn't change position, so they remained unchanged.
            assertEquals(compatibleTransaction1.groupsMerkleRoots[2], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[2])
            assertEquals(compatibleTransaction1.groupsMerkleRoots[4], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[4])
        }
    }
}