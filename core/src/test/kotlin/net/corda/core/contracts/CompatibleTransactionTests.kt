package net.corda.core.contracts

import net.corda.core.contracts.ComponentGroupEnum.*
import net.corda.core.crypto.MerkleTree
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.secureRandomBytes
import net.corda.core.crypto.sha256
import net.corda.core.serialization.serialize
import net.corda.core.transactions.ComponentGroup
import net.corda.core.transactions.CompatibleTransaction
import net.corda.core.transactions.WireTransaction
import net.corda.core.utilities.OpaqueBytes
import net.corda.testing.*
import net.corda.testing.contracts.DummyContract
import org.junit.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class CompatibleTransactionTests : TestDependencyInjectionBase() {

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
        assertEquals(SecureHash.zeroHash, compatibleTransactionEmptyOutputs.groupsMerkleRoots[OUTPUTS_GROUP.ordinal])

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
        assertNotEquals(compatibleTransaction1.groupsMerkleRoots[INPUTS_GROUP.ordinal], compatibleTransaction1ShuffledInputs.groupsMerkleRoots[INPUTS_GROUP.ordinal])
        // But outputs group Merkle leaf (and the rest) remained the same.
        assertEquals(compatibleTransaction1.groupsMerkleRoots[OUTPUTS_GROUP.ordinal], compatibleTransaction1ShuffledInputs.groupsMerkleRoots[OUTPUTS_GROUP.ordinal])
        assertEquals(compatibleTransaction1.groupsMerkleRoots[ATTACHMENTS_GROUP.ordinal], compatibleTransaction1ShuffledInputs.groupsMerkleRoots[ATTACHMENTS_GROUP.ordinal])

        val shuffledComponentGroupsA = listOf(outputGroup, inputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)
        val compatibleTransaction1ShuffledGroups = CompatibleTransaction(componentGroups = shuffledComponentGroupsA, privacySalt = privacySalt)

        // Group leaves ordering matters. We should keep a standardised sequence for backwards/forwards compatibility.
        // For instance inputs should always be the first leaf, then outputs, the commands etc.
        assertNotEquals(compatibleTransaction1, compatibleTransaction1ShuffledGroups)
        assertNotEquals(compatibleTransaction1.merkleTree, compatibleTransaction1ShuffledGroups.merkleTree)
        // First leaf (Merkle root) is not equal.
        assertNotEquals(compatibleTransaction1.groupsMerkleRoots[INPUTS_GROUP.ordinal], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[INPUTS_GROUP.ordinal])
        // Second leaf (Merkle leaf) is not equal.
        assertNotEquals(compatibleTransaction1.groupsMerkleRoots[OUTPUTS_GROUP.ordinal], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[OUTPUTS_GROUP.ordinal])
        // Actually, because the index participate in nonces, swapping group-leaves changes the Merkle roots.
        assertNotEquals(compatibleTransaction1.groupsMerkleRoots[INPUTS_GROUP.ordinal], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[OUTPUTS_GROUP.ordinal])
        assertNotEquals(compatibleTransaction1.groupsMerkleRoots[OUTPUTS_GROUP.ordinal], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[INPUTS_GROUP.ordinal])
        // However third leaf (index=2), as well as the rest, didn't change position, so they remained unchanged.
        assertEquals(compatibleTransaction1.groupsMerkleRoots[COMMANDS_GROUP.ordinal], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[COMMANDS_GROUP.ordinal])
        assertEquals(compatibleTransaction1.groupsMerkleRoots[NOTARY_GROUP.ordinal], compatibleTransaction1ShuffledGroups.groupsMerkleRoots[NOTARY_GROUP.ordinal])
    }

    @Test
    fun `WireTransaction constructors and compatibility`() {
        val inputGroup = ComponentGroup(inputs.map { it -> it.serialize() })
        val outputGroup = ComponentGroup(outputs.map { it -> it.serialize() })
        val commandGroup = ComponentGroup(commands.map { it -> it.serialize() })
        val attachmentGroup = ComponentGroup(attachments.map { it -> it.serialize() }) // The list is empty.
        val notaryGroup = ComponentGroup(listOf(notary.serialize()))
        val timeWindowGroup = ComponentGroup(listOf(timeWindow.serialize()))

        val componentGroupsA = listOf(inputGroup, outputGroup, commandGroup, attachmentGroup, notaryGroup, timeWindowGroup)

        val wireTransactionOld = WireTransaction(inputs, attachments, outputs, commands, notary, timeWindow, privacySalt)
        val wireTransactionNew = WireTransaction(componentGroupsA, privacySalt)
        assertEquals(wireTransactionNew, wireTransactionOld)

        // Malformed tx - attachments (index = 3) is not List<SecureHash>.
        val componentGroupsB = listOf(inputGroup, outputGroup, commandGroup, inputGroup, notaryGroup, timeWindowGroup)
        assertFailsWith<ClassCastException> { WireTransaction(componentGroupsB, privacySalt) }

        val componentGroupsCompatibleA = listOf(
                inputGroup,
                outputGroup,
                commandGroup,
                attachmentGroup,
                notaryGroup,
                timeWindowGroup,
                ComponentGroup(listOf(OpaqueBytes(secureRandomBytes(4)), OpaqueBytes(secureRandomBytes(8)))) // A new component we don't know about.
        )

        // The old client (receiving more component types than expected) is still compatible.
        val wireTransactionCompatibleA = WireTransaction(componentGroupsCompatibleA, privacySalt)
        assertEquals(wireTransactionCompatibleA.inputs, wireTransactionNew.inputs)
        assertNotEquals(wireTransactionCompatibleA, wireTransactionNew)

        val componentGroupsCompatibleB = listOf(
                inputGroup,
                outputGroup,
                commandGroup,
                attachmentGroup,
                notaryGroup,
                timeWindowGroup,
                ComponentGroup(emptyList()) // A new empty component we don't know about.
        )
        // The old client (receiving more component types than expected, even if empty) is still compatible.
        val wireTransactionCompatibleB = WireTransaction(componentGroupsCompatibleB, privacySalt)
        assertEquals(wireTransactionCompatibleB.inputs, wireTransactionNew.inputs)
        assertNotEquals(wireTransactionCompatibleB, wireTransactionNew) // Although the last component is empty, transactions are not equal.
    }
}
