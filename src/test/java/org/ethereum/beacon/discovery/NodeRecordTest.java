/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static org.ethereum.beacon.discovery.TestUtil.SEED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.EnrFieldV4;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.IdentitySchemaV4Interpreter;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.ethereum.beacon.discovery.util.Functions;
import org.javatuples.Pair;
import org.junit.jupiter.api.Test;

/**
 * ENR serialization/deserialization test
 *
 * <p>ENR - Ethereum Node Record, according to <a
 * href="https://eips.ethereum.org/EIPS/eip-778">https://eips.ethereum.org/EIPS/eip-778</a>
 */
public class NodeRecordTest {
  private static final NodeRecordFactory NODE_RECORD_FACTORY = NodeRecordFactory.DEFAULT;

  @Test
  public void testLocalhostV4() throws Exception {
    final String expectedHost = "127.0.0.1";
    final Integer expectedUdpPort = 30303;
    final UInt64 expectedSeqNumber = UInt64.valueOf(1);
    final Bytes expectedPublicKey =
        Bytes.fromHexString("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138");
    final Bytes expectedSignature =
        Bytes.fromHexString(
            "7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c");

    final String localhostEnr =
        "-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
    NodeRecord nodeRecord = NODE_RECORD_FACTORY.fromBase64(localhostEnr);

    assertEquals(IdentitySchema.V4, nodeRecord.getIdentityScheme());
    assertArrayEquals(
        InetAddress.getByName(expectedHost).getAddress(),
        ((Bytes) nodeRecord.get(EnrField.IP_V4)).toArray());
    assertEquals(expectedUdpPort, nodeRecord.get(EnrField.UDP_V4));
    //    assertEquals(expectedTcpPort, nodeRecord.get(EnrField.TCP_V4));
    assertEquals(expectedSeqNumber, nodeRecord.getSeq());
    assertEquals(expectedPublicKey, nodeRecord.get(EnrFieldV4.PKEY_SECP256K1));
    assertEquals(expectedSignature, nodeRecord.getSignature());

    String localhostEnrRestored = nodeRecord.asBase64();
    // The order of fields is not strict so we don't compare strings
    NodeRecord nodeRecordRestored = NODE_RECORD_FACTORY.fromBase64(localhostEnrRestored);

    assertEquals(IdentitySchema.V4, nodeRecordRestored.getIdentityScheme());
    assertArrayEquals(
        InetAddress.getByName(expectedHost).getAddress(),
        ((Bytes) nodeRecordRestored.get(EnrField.IP_V4)).toArray());
    assertEquals(expectedUdpPort, nodeRecordRestored.get(EnrField.UDP_V4));
    //    assertEquals(expectedTcpPort, nodeRecordRestored.get(EnrField.TCP_V4));
    assertEquals(expectedSeqNumber, nodeRecordRestored.getSeq());
    assertEquals(expectedPublicKey, nodeRecordRestored.get(EnrFieldV4.PKEY_SECP256K1));
    assertEquals(expectedSignature, nodeRecordRestored.getSignature());
  }

  @Test
  public void testSignature() throws Exception {
    Random rnd = new Random(SEED);
    byte[] privKey = new byte[32];
    rnd.nextBytes(privKey);
    Bytes localIp = Bytes.wrap(InetAddress.getByName("127.0.0.1").getAddress());
    NodeRecord nodeRecord0 =
        NodeRecordFactory.DEFAULT.createFromValues(
            UInt64.ZERO,
            Pair.with(EnrField.ID, IdentitySchema.V4),
            Pair.with(EnrField.IP_V4, localIp),
            //            Pair.with(EnrField.TCP_V4, 30303),
            Pair.with(EnrField.UDP_V4, 30303),
            Pair.with(
                EnrFieldV4.PKEY_SECP256K1,
                Functions.derivePublicKeyFromPrivate(Bytes.wrap(privKey))));
    nodeRecord0.sign(Bytes.wrap(privKey));
    nodeRecord0.verify();
    NodeRecord nodeRecord1 =
        NodeRecordFactory.DEFAULT.createFromValues(
            UInt64.valueOf(1),
            Pair.with(EnrField.ID, IdentitySchema.V4),
            Pair.with(EnrField.IP_V4, localIp),
            //            Pair.with(EnrField.TCP_V4, 30303),
            Pair.with(EnrField.UDP_V4, 30303),
            Pair.with(
                EnrFieldV4.PKEY_SECP256K1,
                Functions.derivePublicKeyFromPrivate(Bytes.wrap(privKey))));
    nodeRecord1.sign(Bytes.wrap(privKey));
    nodeRecord1.verify();
    assertNotEquals(nodeRecord0.serialize(), nodeRecord1.serialize());
    assertNotEquals(nodeRecord0.getSignature(), nodeRecord1.getSignature());
    nodeRecord1.setSignature(nodeRecord0.getSignature());
    AtomicBoolean exceptionThrown = new AtomicBoolean(false);
    try {
      nodeRecord1.verify();
    } catch (AssertionError ex) {
      exceptionThrown.set(true);
    }
    assertTrue(exceptionThrown.get());
  }

  @Test
  public void shouldNotIncludePaddingInBase64() {
    final int port = 30303;
    final Bytes ip = Bytes.fromHexString("0x7F000001");
    final Bytes nodeId =
        Bytes.fromHexString("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    final Bytes privateKey =
        Bytes.fromHexString("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    final int seq = 1;

    NodeRecord nodeRecord =
        new NodeRecordFactory(new IdentitySchemaV4Interpreter())
            .createFromValues(
                UInt64.valueOf(seq),
                Pair.with(EnrField.ID, IdentitySchema.V4),
                Pair.with(EnrFieldV4.IP_V4, ip),
                Pair.with(EnrFieldV4.UDP_V4, port),
                Pair.with(
                    EnrFieldV4.PKEY_SECP256K1, Functions.derivePublicKeyFromPrivate(privateKey)));
    nodeRecord.sign(privateKey);
    assertEquals(nodeId, nodeRecord.getNodeId());
    assertEquals(
        "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8",
        nodeRecord.asEnr());
  }

  @Test
  public void shouldDecodeEnr() {
    final NodeRecordFactory nodeRecordFactory =
        new NodeRecordFactory(new IdentitySchemaV4Interpreter());
    final NodeRecord nodeRecord =
        nodeRecordFactory.fromBase64(
            "-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8");
    final Bytes nodeId =
        Bytes.fromHexString("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    assertEquals(nodeId, nodeRecord.getNodeId());
    assertEquals(UInt64.valueOf(1), nodeRecord.getSeq());
    assertEquals(
        Bytes.fromHexString("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138"),
        nodeRecord.get(EnrFieldV4.PKEY_SECP256K1));
    assertEquals(Bytes.fromHexString("0x7F000001"), nodeRecord.get(EnrField.IP_V4));
    assertEquals(30303, nodeRecord.get(EnrField.UDP_V4));
  }
}
