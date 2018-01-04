package net.corda.core.crypto

import net.corda.core.serialization.serialize
import net.corda.testing.SerializationEnvironmentRule
import org.junit.Rule
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import java.security.*
import kotlin.test.assertFailsWith

/**
 * Digital signature MetaData tests.
 */
class TransactionSignatureTest {
    @Rule
    @JvmField
    val testSerialization = SerializationEnvironmentRule()
    private val testBytes = "12345678901234567890123456789012".toByteArray()

    /** Valid sign and verify. */
    @Test
    fun `Signature metadata full sign and verify`() {
        val txID = testBytes.sha256()
        val keyPair = Crypto.generateKeyPair(Crypto.ECDSA_SECP256K1_SHA256)

        // Create a SignableData object.
        val signableData = SignableData(txID, SignatureMetadata(1, Crypto.findSignatureScheme(keyPair.public).schemeNumberID))

        // Sign the meta object.
        val transactionSignature: TransactionSignature = keyPair.sign(signableData)

        // Check auto-verification.
        assertTrue(transactionSignature.verify(txID))

        // Check manual verification.
        assertTrue(Crypto.doVerify(txID, transactionSignature))
    }

    /** Verification should fail; corrupted metadata - clearData (Merkle root) has changed. */
    @Test(expected = SignatureException::class)
    fun `Signature metadata full failure clearData has changed`() {
        val keyPair = Crypto.generateKeyPair(Crypto.ECDSA_SECP256K1_SHA256)
        val signableData = SignableData(testBytes.sha256(), SignatureMetadata(1, Crypto.findSignatureScheme(keyPair.public).schemeNumberID))
        val transactionSignature = keyPair.sign(signableData)
        Crypto.doVerify((testBytes + testBytes).sha256(), transactionSignature)
    }

    @Test
    fun `Sign wrong metadata scheme`() {
        val txID = testBytes.sha256()

        // Test for ECDSA-R1, using a wrong Metadata scheme (intended for ECDSA K1).
        val keyPairECDSA_R1 = Crypto.generateKeyPair(Crypto.ECDSA_SECP256R1_SHA256)
        assertEquals(3, Crypto.findSignatureScheme(keyPairECDSA_R1.public).schemeNumberID)

        // Create a SignableData object.
        val k1_schemeNumberID = 2
        val signableDataForK1 = SignableData(txID, SignatureMetadata(1, k1_schemeNumberID))

        // Sign the meta object.
        assertFailsWith<IllegalArgumentException> { keyPairECDSA_R1.sign(signableDataForK1) }

        // Test for EdDSA ed25519, using a wrong Metadata scheme (intended for RSA).
        val keyPairEdDSA = Crypto.generateKeyPair(Crypto.EDDSA_ED25519_SHA512)
        assertEquals(4, Crypto.findSignatureScheme(keyPairEdDSA.public).schemeNumberID)

        // Create a SignableData object.
        val rsa_schemeNumberID = 1
        val signableDataEdDSA = SignableData(txID, SignatureMetadata(1, rsa_schemeNumberID))

        // Sign the meta object.
        assertFailsWith<IllegalArgumentException> { keyPairEdDSA.sign(signableDataEdDSA) }
    }

    @Test
    fun `Verify wrong metadata scheme`() {
        val txID = testBytes.sha256()

        // Test for ECDSA-R1, using a wrong Metadata scheme (intended for ECDSA K1).
        val keyPairECDSA_R1 = Crypto.generateKeyPair(Crypto.ECDSA_SECP256R1_SHA256)

        // Create a SignableData object.
        val k1_schemeNumberID = 2
        val signableDataForK1 = SignableData(txID, SignatureMetadata(1, k1_schemeNumberID))

        // Sign the meta object.
        // Not using keyPair.sign(signableData) or doSign(keyPair, signableData) because
        // it won't let me sign a wrong Metadata object; we are only testing verification of potentially malicious Metadata.
        val signatureBytesR1 = Crypto.doSign(Crypto.findSignatureScheme(keyPairECDSA_R1.private), keyPairECDSA_R1.private, signableDataForK1.serialize().bytes)
        val txSignatureR1 = TransactionSignature(signatureBytesR1, keyPairECDSA_R1.public, signableDataForK1.signatureMetadata)
        assertFailsWith<IllegalArgumentException> { Crypto.doVerify(txID, txSignatureR1) }

        // Test for EdDSA ed25519, using a wrong Metadata scheme (intended for RSA).
        val keyPairEdDSA = Crypto.generateKeyPair(Crypto.EDDSA_ED25519_SHA512)

        // Create a SignableData object.
        val rsa_schemeNumberID = 1
        val signableDataEdDSA = SignableData(txID, SignatureMetadata(1, rsa_schemeNumberID))

        // Sign the meta object.
        val signatureBytesEdDSA = Crypto.doSign(Crypto.findSignatureScheme(keyPairEdDSA.private), keyPairEdDSA.private, signableDataEdDSA.serialize().bytes)
        val txSignatureEdDSA = TransactionSignature(signatureBytesEdDSA, keyPairEdDSA.public, signableDataEdDSA.signatureMetadata)
        assertFailsWith<IllegalArgumentException> { Crypto.doVerify(txID, txSignatureEdDSA) }
    }
}
