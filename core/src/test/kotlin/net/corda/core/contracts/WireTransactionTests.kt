package net.corda.core.contracts

import net.corda.core.crypto.MerkleTree
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.sha256
import net.corda.core.serialization.serialize
import net.corda.core.transactions.ComponentGroup
import net.corda.core.transactions.SerialisedTransaction
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

            val serTransaction1 = SerialisedTransaction(componentGroups = componentGroupsA, privacySalt = privacySalt)
            val serTransaction2 = SerialisedTransaction(componentGroups = componentGroupsA, privacySalt = privacySalt)

            // Merkle tree computation is deterministic.
            assertEquals(serTransaction1.merkleTree, serTransaction2.merkleTree)

            // Full Merkle root is computed from the list of Merkle roots of each component group.
            assertEquals(serTransaction1.merkleTree, MerkleTree.getMerkleTree(listOf(privacySalt.sha256()) + serTransaction1.groupsMerkleRoots))

            val componentGroupsEmptyOutputs = listOf(inputGroup, ComponentGroup(emptyList()), commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
            val serTransactionEmptyOutputs = SerialisedTransaction(componentGroups = componentGroupsEmptyOutputs, privacySalt = privacySalt)

            // Because outputs list is empty, it should be zeroHash.
            assertEquals(SecureHash.zeroHash, serTransactionEmptyOutputs.groupsMerkleRoots[1])

            // TXs differ in outputStates.
            assertNotEquals(serTransaction1.merkleTree, serTransactionEmptyOutputs.merkleTree)

            val inputsShuffled = listOf(stateRef2, stateRef1, stateRef3)
            val inputShuffledGroup = ComponentGroup(inputsShuffled.map { it -> it.serialize() })
            val componentGroupsB = listOf(inputShuffledGroup, outputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
            val serTransaction1ShuffledInputs = SerialisedTransaction(componentGroups = componentGroupsB, privacySalt = privacySalt)

            // Ordering inside a component group matters.
            assertNotEquals(serTransaction1, serTransaction1ShuffledInputs)
            assertNotEquals(serTransaction1.merkleTree, serTransaction1ShuffledInputs.merkleTree)
            // Inputs group Merkle root is not equal.
            assertNotEquals(serTransaction1.groupsMerkleRoots[0], serTransaction1ShuffledInputs.groupsMerkleRoots[0])
            // But outputs group Merkle leaf (and the rest) remained the same.
            assertEquals(serTransaction1.groupsMerkleRoots[1], serTransaction1ShuffledInputs.groupsMerkleRoots[1])
            assertEquals(serTransaction1.groupsMerkleRoots[3], serTransaction1ShuffledInputs.groupsMerkleRoots[3])

            val shuffledComponentGroupsA = listOf(outputGroup, inputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
            val serTransaction1ShuffledGroups = SerialisedTransaction(componentGroups = shuffledComponentGroupsA, privacySalt = privacySalt)

            // Ordering in the group leafs matters. We should keep a standardised sequence for backwards/forwards compatibility.
            // For instance inputs should always be the first leaf, then outputs, the commands etc.
            assertNotEquals(serTransaction1, serTransaction1ShuffledGroups)
            assertNotEquals(serTransaction1.merkleTree, serTransaction1ShuffledGroups.merkleTree)
            // First leaf (Merkle root) is not equal.
            assertNotEquals(serTransaction1.groupsMerkleRoots[0], serTransaction1ShuffledGroups.groupsMerkleRoots[0])
            // Second leaf (Merkle leaf) is not equal.
            assertNotEquals(serTransaction1.groupsMerkleRoots[1], serTransaction1ShuffledGroups.groupsMerkleRoots[1])
            // Actually, because the index participate in nonces, swapping group-leafs changes the Merkle roots.
            assertNotEquals(serTransaction1.groupsMerkleRoots[0], serTransaction1ShuffledGroups.groupsMerkleRoots[1])
            assertNotEquals(serTransaction1.groupsMerkleRoots[1], serTransaction1ShuffledGroups.groupsMerkleRoots[0])
            // However third leaf (and the rest) didn't change position, so they remained unchanged.
            assertEquals(serTransaction1.groupsMerkleRoots[2], serTransaction1ShuffledGroups.groupsMerkleRoots[2])
            assertEquals(serTransaction1.groupsMerkleRoots[4], serTransaction1ShuffledGroups.groupsMerkleRoots[4])
        }
    }
}