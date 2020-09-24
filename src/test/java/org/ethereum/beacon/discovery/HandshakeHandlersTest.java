/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static org.ethereum.beacon.discovery.TestUtil.NODE_RECORD_FACTORY_NO_VERIFICATION;
import static org.ethereum.beacon.discovery.TestUtil.TEST_SERIALIZER;
import static org.ethereum.beacon.discovery.pipeline.Field.BAD_PACKET;
import static org.ethereum.beacon.discovery.pipeline.Field.MESSAGE;
import static org.ethereum.beacon.discovery.pipeline.Field.PACKET_AUTH_HEADER_MESSAGE;
import static org.ethereum.beacon.discovery.pipeline.Field.PACKET_MESSAGE;
import static org.ethereum.beacon.discovery.pipeline.Field.SESSION;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.TestUtil.NodeInfo;
import org.ethereum.beacon.discovery.database.Database;
import org.ethereum.beacon.discovery.network.NetworkParcel;
import org.ethereum.beacon.discovery.packet.AuthHeaderMessagePacket;
import org.ethereum.beacon.discovery.packet.MessagePacket;
import org.ethereum.beacon.discovery.packet.Packet;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.ethereum.beacon.discovery.pipeline.Pipeline;
import org.ethereum.beacon.discovery.pipeline.PipelineImpl;
import org.ethereum.beacon.discovery.pipeline.handler.AuthHeaderMessagePacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.MessageHandler;
import org.ethereum.beacon.discovery.pipeline.handler.MessagePacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.WhoAreYouPacketHandler;
import org.ethereum.beacon.discovery.scheduler.ExpirationScheduler;
import org.ethereum.beacon.discovery.scheduler.ExpirationSchedulerFactory;
import org.ethereum.beacon.discovery.scheduler.Scheduler;
import org.ethereum.beacon.discovery.scheduler.Schedulers;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeSession;
import org.ethereum.beacon.discovery.storage.AuthTagRepository;
import org.ethereum.beacon.discovery.storage.LocalNodeRecordStore;
import org.ethereum.beacon.discovery.storage.NodeBucketStorage;
import org.ethereum.beacon.discovery.storage.NodeRecordListener;
import org.ethereum.beacon.discovery.storage.NodeTableStorage;
import org.ethereum.beacon.discovery.storage.NodeTableStorageFactoryImpl;
import org.ethereum.beacon.discovery.task.TaskMessageFactory;
import org.ethereum.beacon.discovery.task.TaskOptions;
import org.ethereum.beacon.discovery.task.TaskType;
import org.ethereum.beacon.discovery.util.Functions;
import org.junit.jupiter.api.Test;
import org.web3j.rlp.RlpDecoder;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;

@SuppressWarnings({"DoubleBraceInitialization"})
public class HandshakeHandlersTest {

  @Test
  public void authHandlerWithMessageRoundTripTest() throws Exception {
    // Node1
    NodeInfo nodePair1 = TestUtil.generateUnverifiedNode(30303);
    NodeRecord nodeRecord1 = nodePair1.getNodeRecord();
    // Node2
    NodeInfo nodePair2 = TestUtil.generateUnverifiedNode(30304);
    NodeRecord nodeRecord2 = nodePair2.getNodeRecord();
    Random rnd = new Random();
    NodeTableStorageFactoryImpl nodeTableStorageFactory = new NodeTableStorageFactoryImpl();
    Database database1 = Database.inMemoryDB();
    Database database2 = Database.inMemoryDB();
    NodeTableStorage nodeTableStorage1 =
        nodeTableStorageFactory.createTable(
            database1,
            TEST_SERIALIZER,
            (oldSeq) -> nodeRecord1,
            () ->
                new ArrayList<NodeRecord>() {
                  {
                    add(nodeRecord2);
                  }
                });
    NodeBucketStorage nodeBucketStorage1 =
        nodeTableStorageFactory.createBucketStorage(database1, TEST_SERIALIZER, nodeRecord1);
    NodeTableStorage nodeTableStorage2 =
        nodeTableStorageFactory.createTable(
            database2,
            TEST_SERIALIZER,
            (oldSeq) -> nodeRecord2,
            () ->
                new ArrayList<NodeRecord>() {
                  {
                    add(nodeRecord1);
                  }
                });
    NodeBucketStorage nodeBucketStorage2 =
        nodeTableStorageFactory.createBucketStorage(database2, TEST_SERIALIZER, nodeRecord2);

    // Node1 create AuthHeaderPacket
    final Packet[] outgoing1Packets = new Packet[2];
    final Semaphore outgoing1PacketsSemaphore = new Semaphore(2);
    outgoing1PacketsSemaphore.acquire(2);
    final Consumer<NetworkParcel> outgoingMessages1to2 =
        parcel -> {
          System.out.println("Outgoing packet from 1 to 2: " + parcel.getPacket());
          outgoing1Packets[outgoing1PacketsSemaphore.availablePermits()] = parcel.getPacket();
          outgoing1PacketsSemaphore.release(1);
        };
    AuthTagRepository authTagRepository1 = new AuthTagRepository();
    final LocalNodeRecordStore localNodeRecordStoreAt1 =
        new LocalNodeRecordStore(nodeRecord1, nodePair1.getPrivateKey(), NodeRecordListener.NOOP);
    final ExpirationSchedulerFactory expirationSchedulerFactory =
        new ExpirationSchedulerFactory(Executors.newSingleThreadScheduledExecutor());
    final ExpirationScheduler<Bytes> reqeustExpirationScheduler =
        expirationSchedulerFactory.create(60, TimeUnit.SECONDS);
    NodeSession nodeSessionAt1For2 =
        new NodeSession(
            nodeRecord2.getNodeId(),
            Optional.of(nodeRecord2),
            nodePair2.getNodeRecord().getUdpAddress().orElseThrow(),
            localNodeRecordStoreAt1,
            nodePair1.getPrivateKey(),
            nodeTableStorage1.get(),
            nodeBucketStorage1,
            authTagRepository1,
            outgoingMessages1to2,
            rnd,
            reqeustExpirationScheduler);
    final Consumer<NetworkParcel> outgoingMessages2to1 =
        packet -> {
          // do nothing, we don't need to test it here
        };
    NodeSession nodeSessionAt2For1 =
        new NodeSession(
            nodeRecord1.getNodeId(),
            Optional.of(nodeRecord1),
            nodeRecord1.getUdpAddress().orElseThrow(),
            new LocalNodeRecordStore(
                nodeRecord2, nodePair2.getPrivateKey(), NodeRecordListener.NOOP),
            nodePair2.getPrivateKey(),
            nodeTableStorage2.get(),
            nodeBucketStorage2,
            new AuthTagRepository(),
            outgoingMessages2to1,
            rnd,
            reqeustExpirationScheduler);

    Scheduler taskScheduler = Schedulers.createDefault().events();
    Pipeline outgoingPipeline = new PipelineImpl().build();
    WhoAreYouPacketHandler whoAreYouPacketHandlerNode1 =
        new WhoAreYouPacketHandler(outgoingPipeline, taskScheduler);
    Envelope envelopeAt1From2 = new Envelope();
    byte[] idNonceBytes = new byte[32];
    Functions.getRandom().nextBytes(idNonceBytes);
    Bytes idNonce = Bytes.wrap(idNonceBytes);
    nodeSessionAt2For1.setIdNonce(idNonce);
    Bytes authTag = nodeSessionAt2For1.generateNonce();
    authTagRepository1.put(authTag, nodeSessionAt1For2);
    envelopeAt1From2.put(
        Field.PACKET_WHOAREYOU,
        WhoAreYouPacket.createFromNodeId(
            nodePair1.getNodeRecord().getNodeId(), authTag, idNonce, UInt64.ZERO));
    envelopeAt1From2.put(Field.SESSION, nodeSessionAt1For2);
    CompletableFuture<Void> future = new CompletableFuture<>();
    nodeSessionAt1For2.createNextRequest(TaskType.FINDNODE, new TaskOptions(true), future);
    whoAreYouPacketHandlerNode1.handle(envelopeAt1From2);
    assertTrue(outgoing1PacketsSemaphore.tryAcquire(1, 1, TimeUnit.SECONDS));
    outgoing1PacketsSemaphore.release();

    // Node2 handle AuthHeaderPacket and finish handshake
    AuthHeaderMessagePacketHandler authHeaderMessagePacketHandlerNode2 =
        new AuthHeaderMessagePacketHandler(
            outgoingPipeline, taskScheduler, NODE_RECORD_FACTORY_NO_VERIFICATION);
    Envelope envelopeAt2From1 = new Envelope();
    AuthHeaderMessagePacket original = (AuthHeaderMessagePacket) outgoing1Packets[0];
//    assertFalse(nodeSessionAt2For1.isAuthenticated());
    Long start = System.nanoTime();
//    AuthHeaderMessagePacket modified = new AuthHeaderMessagePacket(original.getBytes().slice(0, original.getBytes().size() - 1));
    Bytes correctAuthHeader = original.getAuthHeader();
    RlpList list = RlpDecoder.decode(correctAuthHeader.toArray());
    RlpList insideList = (RlpList) list.getValues().get(0);
    RlpString correctIdNonce  = (RlpString) insideList.getValues().get(1);
    byte[] idNonceBytes2 = correctIdNonce.getBytes();
    if (idNonceBytes2[idNonceBytes2.length - 1]  == (byte) 134) {
      idNonceBytes2[idNonceBytes2.length - 1] = (byte) 133;
    } else {
      idNonceBytes2[idNonceBytes2.length - 1] = (byte) 134;
    }
    RlpString incorrectIdNonce = RlpString.create(idNonceBytes2);
    List<RlpType> badHeader = new ArrayList<>();
    badHeader.add(insideList.getValues().get(0));
    badHeader.add(incorrectIdNonce);
    badHeader.add(insideList.getValues().get(2));
    badHeader.add(insideList.getValues().get(3));
    badHeader.add(insideList.getValues().get(4));
    AuthHeaderMessagePacket modified = AuthHeaderMessagePacket.create(
            original.getTag(),
            Bytes.wrap(RlpEncoder.encode(new RlpList(badHeader))),
            original.getEncryptedMessage()
    );
    for (int i = 0; i < 1000; ++i) {
      envelopeAt2From1.put(PACKET_AUTH_HEADER_MESSAGE, modified);
      envelopeAt2From1.put(SESSION, nodeSessionAt2For1);
      authHeaderMessagePacketHandlerNode2.handle(envelopeAt2From1);
      assertFalse(nodeSessionAt2For1.isAuthenticated());
    }
    System.out.println("Total time: " + (System.nanoTime() - start)/1_000_000L + "ms");
    Envelope envelopeAt2From1Correct = new Envelope();
    envelopeAt2From1Correct.put(PACKET_AUTH_HEADER_MESSAGE, original);
    envelopeAt2From1Correct.put(SESSION, nodeSessionAt2For1);
    authHeaderMessagePacketHandlerNode2.handle(envelopeAt2From1Correct);
    assertTrue(nodeSessionAt2For1.isAuthenticated());

    // Node 1 handles message from Node 2
    MessagePacketHandler messagePacketHandler1 = new MessagePacketHandler();
    Envelope envelopeAt1From2WithMessage = new Envelope();
    Bytes pingAuthTag = nodeSessionAt1For2.generateNonce();
    MessagePacket pingPacketFrom2To1 =
        TaskMessageFactory.createPingPacket(
            pingAuthTag,
            nodeSessionAt2For1,
            nodeSessionAt2For1
                .createNextRequest(TaskType.PING, new TaskOptions(true), new CompletableFuture<>())
                .getRequestId());
    envelopeAt1From2WithMessage.put(PACKET_MESSAGE, pingPacketFrom2To1);
    envelopeAt1From2WithMessage.put(SESSION, nodeSessionAt1For2);
    messagePacketHandler1.handle(envelopeAt1From2WithMessage);
    assertNull(envelopeAt1From2WithMessage.get(BAD_PACKET));
    assertNotNull(envelopeAt1From2WithMessage.get(MESSAGE));

    MessageHandler messageHandler =
        new MessageHandler(NODE_RECORD_FACTORY_NO_VERIFICATION, localNodeRecordStoreAt1);
    messageHandler.handle(envelopeAt1From2WithMessage);
    assertTrue(outgoing1PacketsSemaphore.tryAcquire(2, 1, TimeUnit.SECONDS));

    // Node 2 handles message from Node 1
    MessagePacketHandler messagePacketHandler2 = new MessagePacketHandler();
    Envelope envelopeAt2From1WithMessage = new Envelope();
    Packet pongPacketFrom1To2 = outgoing1Packets[1];
    MessagePacket pongMessagePacketFrom1To2 = (MessagePacket) pongPacketFrom1To2;
    envelopeAt2From1WithMessage.put(PACKET_MESSAGE, pongMessagePacketFrom1To2);
    envelopeAt2From1WithMessage.put(SESSION, nodeSessionAt2For1);
    messagePacketHandler2.handle(envelopeAt2From1WithMessage);
    assertNull(envelopeAt2From1WithMessage.get(BAD_PACKET));
    assertNotNull(envelopeAt2From1WithMessage.get(MESSAGE));
  }
}
