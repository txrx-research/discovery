/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static org.ethereum.beacon.discovery.packet.AuthHeaderMessagePacket.createIdNonceMessage;
import static org.ethereum.beacon.discovery.util.Functions.PRIVKEY_SIZE;
import static org.ethereum.beacon.discovery.util.Functions.PUBKEY_SIZE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.math.ec.ECPoint;
import org.ethereum.beacon.discovery.packet.AuthHeaderMessagePacket;
import org.ethereum.beacon.discovery.util.Functions;
import org.ethereum.beacon.discovery.util.Functions.HKDFKeys;
import org.ethereum.beacon.discovery.util.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.ECKeyPair;

import java.util.Random;

public class FunctionsTest {
  private final Bytes testKey1 =
      Bytes.fromHexString("3332ca2b7003810449b6e596c3d284e914a1a51c9f76e4d9d7d43ef84adf6ed6");
  private final Bytes testKey2 =
      Bytes.fromHexString("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628");
  private Bytes nodeId1;
  private Bytes nodeId2;

  public FunctionsTest() {
    byte[] homeNodeIdBytes = new byte[32];
    homeNodeIdBytes[0] = 0x01;
    byte[] destNodeIdBytes = new byte[32];
    destNodeIdBytes[0] = 0x02;
    this.nodeId1 = Bytes.wrap(homeNodeIdBytes);
    this.nodeId2 = Bytes.wrap(destNodeIdBytes);
  }

  @Test
  public void testLogDistance() {
    Bytes nodeId0 =
        Bytes.fromHexString("0000000000000000000000000000000000000000000000000000000000000000");
    Bytes nodeId1a =
        Bytes.fromHexString("0000000000000000000000000000000000000000000000000000000000000001");
    Bytes nodeId1b =
        Bytes.fromHexString("1000000000000000000000000000000000000000000000000000000000000000");
    Bytes nodeId1s =
        Bytes.fromHexString("1111111111111111111111111111111111111111111111111111111111111111");
    Bytes nodeId9s =
        Bytes.fromHexString("9999999999999999999999999999999999999999999999999999999999999999");
    Bytes nodeIdfs =
        Bytes.fromHexString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assertEquals(0, Functions.logDistance(nodeId1a, nodeId1a));
    assertEquals(1, Functions.logDistance(nodeId0, nodeId1a));
    // So it's big endian
    assertEquals(253, Functions.logDistance(nodeId0, nodeId1b));
    assertEquals(253, Functions.logDistance(nodeId0, nodeId1s));
    assertEquals(256, Functions.logDistance(nodeId0, nodeId9s));
    // maximum distance
    assertEquals(256, Functions.logDistance(nodeId0, nodeIdfs));
    // logDistance is not an additive function
    assertEquals(255, Functions.logDistance(nodeId9s, nodeIdfs));
  }

  @Test
  public void hkdfExpandTest() {
    Bytes idNonce =
        Bytes.fromHexString("68b02a985ecb99cc2d10cf188879d93ae7684c4f4707770017b078c6497c5a5d");
    Functions.HKDFKeys keys1 =
        Functions.hkdf_expand(
            nodeId1,
            nodeId2,
            testKey1,
            Bytes.wrap(ECKeyPair.create(testKey2.toArray()).getPublicKey().toByteArray()),
            idNonce);
    Functions.HKDFKeys keys2 =
        Functions.hkdf_expand(
            nodeId1,
            nodeId2,
            testKey2,
            Bytes.wrap(ECKeyPair.create(testKey1.toArray()).getPublicKey().toByteArray()),
            idNonce);
    assertEquals(keys1, keys2);
  }

  @Test
  public void specTestVector_ecdh() {
    final Bytes publicKey =
        Bytes.fromHexString(
            "0x9961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231503061ac4aaee666073d7e5bc2c80c3f5c5b500c1cb5fd0a76abbb6b675ad157");
    final Bytes secretKey =
        Bytes.fromHexString("0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    final Bytes result = Functions.deriveECDHKeyAgreement(secretKey, publicKey);
    assertEquals(
        Bytes.fromHexString("0x033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"),
        result);
  }

  @Test
  public void specTestVector_keyDerivation() {
    final Bytes secretKey =
        Bytes.fromHexString("0x02a77e3aa0c144ae7c0a3af73692b7d6e5b7a2fdc0eda16e8d5e6cb0d08e88dd04");
    final Bytes nodeIdA =
        Bytes.fromHexString("0xa448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    final Bytes nodeIdB =
        Bytes.fromHexString("0x885bba8dfeddd49855459df852ad5b63d13a3fae593f3f9fa7e317fd43651409");
    final Bytes idNonce =
        Bytes.fromHexString("0x0101010101010101010101010101010101010101010101010101010101010101");

    final HKDFKeys hkdfKeys = Functions.hkdf_expand(nodeIdA, nodeIdB, secretKey, idNonce);
    assertEquals(
        Bytes.fromHexString("0x238d8b50e4363cf603a48c6cc3542967"), hkdfKeys.getInitiatorKey());
    assertEquals(
        Bytes.fromHexString("0xbebc0183484f7e7ca2ac32e3d72c8891"), hkdfKeys.getRecipientKey());
    assertEquals(
        Bytes.fromHexString("0xe987ad9e414d5b4f9bfe4ff1e52f2fae"), hkdfKeys.getAuthResponseKey());
  }

  @Test
  public void testGcmSimple() {
    Long counter = 0L;
    Random rnd = new Random();
    for (int i = 0; i < 1000; ++i) {
      Bytes authResponseKey = Bytes.fromHexString("0x60bfc5c924a8d640f47df8b781f5a0e5");
      Bytes authResponsePt =
              Bytes.fromHexString(
                      "0xf8aa05b8404f5fa8309cab170dbeb049de504b519288777aae0c4b25686f82310206a4a1e264dc6e8bfaca9187e8b3dbb56f49c7aa3d22bff3a279bf38fb00cb158b7b8ca7b865f86380018269648276348375647082765f826970847f00000189736563703235366b31b84013d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb97e6adeb003652e807c7f2fe843e0c48d02d4feb0272e2e01f6e27915a431e773");
      byte[] a = new byte[12];
      rnd.nextBytes(a);
      Bytes zeroNonce = Bytes.wrap(a);
      Long start = System.nanoTime();
      Bytes authResponse =
              Functions.aesgcm_encrypt(authResponseKey, zeroNonce, authResponsePt, Bytes.EMPTY);
      counter += System.nanoTime() - start;
      Bytes authResponsePtDecrypted =
              Functions.aesgcm_decrypt(authResponseKey, zeroNonce, authResponse, Bytes.EMPTY);
      assertEquals(authResponsePt, authResponsePtDecrypted);
    }
    System.out.println("Total time: " + counter/1_000_000L + "ms");
  }

  @Test
  @SuppressWarnings({"DefaultCharset"})
  public void testRecoverFromSignature() throws Exception {
    Bytes idNonceSig =
        Bytes.fromHexString(
            "0xcf2bf743fc2273709bbc5117fd72775b0661ce1b6e9dffa01f45e2307fb138b90da16364ee7ae1705b938f6648d7725d35fe7e3f200e0ea022c1360b9b2e7385");
    Bytes ephemeralKey =
        Bytes.fromHexString(
            "0x9961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231503061ac4aaee666073d7e5bc2c80c3f5c5b500c1cb5fd0a76abbb6b675ad157");
    Bytes nonce =
        Bytes.fromHexString("0x02a77e3aa0c144ae7c0a3af73692b7d6e5b7a2fdc0eda16e8d5e6cb0d08e88dd04");
    Bytes privKey =
        Bytes.fromHexString("0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    Bytes pubKeyUncompressed =
        Bytes.wrap(
            Utils.extractBytesFromUnsignedBigInt(
                ECKeyPair.create(privKey.toArray()).getPublicKey(), PUBKEY_SIZE));
    Bytes pubKey = Bytes.wrap(Functions.publicKeyToPoint(pubKeyUncompressed).getEncoded(true));

    Bytes message =
        Bytes.concatenate(Bytes.wrap("discovery-id-nonce".getBytes()), nonce, ephemeralKey);
    Long start = System.nanoTime();
    for (int i = 0; i < 1000; ++i) {
      assertTrue(Functions.verifyECDSASignature(idNonceSig, Functions.hash(message), pubKey));
    }
    System.out.println("Total time: " + (System.nanoTime() - start)/1_000_000L + "ms");
  }

  @Test
  public void testSignAndRecoverFromSignature() {
    Bytes idNonce =
        Bytes.fromHexString("0xd550ca9d62930c947efff75b58a4ea1b44716d841cc0d690879d4f3cab5a4e84");
    Bytes ephemeralPubkey =
        Bytes.fromHexString(
            "0xd9bc9158f0a0c40e75490de66ef44f865588d1c7110b29d0c479db19f7644ddad2d8e948cb933bd767437b173888409d73644a36ae1d068997217357a22d674f");
    Bytes privKey =
        Bytes.fromHexString("0xb5a8efa45da6906663cf7a158cd506da71ae7d732a68220e6644468526bb098e");
    Bytes pubKey =
        Bytes.wrap(
            Functions.publicKeyToPoint(
                    Bytes.wrap(
                        Utils.extractBytesFromUnsignedBigInt(
                            ECKeyPair.create(privKey.toArray()).getPublicKey(), 64)))
                .getEncoded(true));
    Bytes idNonceSig = AuthHeaderMessagePacket.signIdNonce(idNonce, privKey, ephemeralPubkey);
    assertTrue(
        Functions.verifyECDSASignature(
            idNonceSig, Functions.hash(createIdNonceMessage(idNonce, ephemeralPubkey)), pubKey));
  }

  @Test
  public void shouldConvertBetweenPublicKeyForms() {
    final ECKeyPair keyPair = Functions.generateECKeyPair();

    final Bytes privateKey =
        Bytes.wrap(Utils.extractBytesFromUnsignedBigInt(keyPair.getPrivateKey(), PRIVKEY_SIZE));
    final Bytes fullPublicKey =
        Bytes.wrap(Utils.extractBytesFromUnsignedBigInt(keyPair.getPublicKey(), PUBKEY_SIZE));
    final Bytes derivedPublicKey = Functions.derivePublicKeyFromPrivate(privateKey);

    final ECPoint fullPoint = Functions.publicKeyToPoint(fullPublicKey);
    final ECPoint derivedPoint = Functions.publicKeyToPoint(derivedPublicKey);
    Assertions.assertEquals(fullPoint, derivedPoint);
  }
}
