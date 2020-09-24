/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.schema;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.ethereum.beacon.discovery.task.TaskStatus.AWAIT;
import static org.ethereum.beacon.discovery.task.TaskStatus.SENT;

import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.network.NetworkParcel;
import org.ethereum.beacon.discovery.network.NetworkParcelV5;
import org.ethereum.beacon.discovery.packet.Packet;
import org.ethereum.beacon.discovery.pipeline.info.RequestInfo;
import org.ethereum.beacon.discovery.pipeline.info.RequestInfoFactory;
import org.ethereum.beacon.discovery.scheduler.ExpirationScheduler;
import org.ethereum.beacon.discovery.storage.AuthTagRepository;
import org.ethereum.beacon.discovery.storage.LocalNodeRecordStore;
import org.ethereum.beacon.discovery.storage.NodeBucket;
import org.ethereum.beacon.discovery.storage.NodeBucketStorage;
import org.ethereum.beacon.discovery.storage.NodeTable;
import org.ethereum.beacon.discovery.task.TaskOptions;
import org.ethereum.beacon.discovery.task.TaskType;
import org.ethereum.beacon.discovery.util.Functions;

/**
 * Stores session status and all keys for discovery message exchange between us, `homeNode` and the
 * other `node`
 */
public class NodeSession {
  public static final int NONCE_SIZE = 12;
  public static final int REQUEST_ID_SIZE = 8;
  private static final Logger logger = LogManager.getLogger(NodeSession.class);
  private final Bytes homeNodeId;
  private final LocalNodeRecordStore localNodeRecordStore;
  private final AuthTagRepository authTagRepo;
  private final NodeTable nodeTable;
  private final NodeBucketStorage nodeBucketStorage;
  private final InetSocketAddress remoteAddress;
  private final Consumer<NetworkParcel> outgoingPipeline;
  private final Random rnd;
  private final Bytes nodeId;
  private Optional<NodeRecord> nodeRecord;
  private SessionStatus status = SessionStatus.INITIAL;
  private Bytes idNonce;
  private Bytes initiatorKey;
  private Bytes recipientKey;
  private final Map<Bytes, RequestInfo> requestIdStatuses = new ConcurrentHashMap<>();
  private final ExpirationScheduler<Bytes> requestExpirationScheduler;
  private final Bytes staticNodeKey;
  private Optional<InetSocketAddress> reportedExternalAddress = Optional.empty();

  public NodeSession(
      Bytes nodeId,
      Optional<NodeRecord> nodeRecord,
      InetSocketAddress remoteAddress,
      LocalNodeRecordStore localNodeRecordStore,
      Bytes staticNodeKey,
      NodeTable nodeTable,
      NodeBucketStorage nodeBucketStorage,
      AuthTagRepository authTagRepo,
      Consumer<NetworkParcel> outgoingPipeline,
      Random rnd,
      ExpirationScheduler<Bytes> requestExpirationScheduler) {
    this.nodeId = nodeId;
    this.nodeRecord = nodeRecord;
    this.remoteAddress = remoteAddress;
    this.localNodeRecordStore = localNodeRecordStore;
    this.authTagRepo = authTagRepo;
    this.nodeTable = nodeTable;
    this.nodeBucketStorage = nodeBucketStorage;
    this.staticNodeKey = staticNodeKey;
    this.homeNodeId = localNodeRecordStore.getLocalNodeRecord().getNodeId();
    this.outgoingPipeline = outgoingPipeline;
    this.rnd = rnd;
    this.requestExpirationScheduler = requestExpirationScheduler;
  }

  public Bytes getNodeId() {
    return nodeId;
  }

  public Optional<NodeRecord> getNodeRecord() {
    return nodeRecord;
  }

  public InetSocketAddress getRemoteAddress() {
    return remoteAddress;
  }

  public synchronized void updateNodeRecord(NodeRecord nodeRecord) {
    logger.trace(
        () ->
            String.format(
                "NodeRecord updated from %s to %s in session %s",
                this.nodeRecord, nodeRecord, this));
    this.nodeRecord = Optional.of(nodeRecord);
  }

  public void sendOutgoing(Packet packet) {
    logger.trace(() -> String.format("Sending outgoing packet %s in session %s", packet, this));
    outgoingPipeline.accept(new NetworkParcelV5(packet, remoteAddress));
  }

  /**
   * Creates object with request information: requestId etc, RequestInfo, designed to maintain
   * request status and its changes. Also stores info in session repository to track related
   * messages.
   *
   * <p>The value selected as request ID must allow for concurrent conversations. Using a timestamp
   * can result in parallel conversations with the same id, so this should be avoided. Request IDs
   * also prevent replay of responses. Using a simple counter would be fine if the implementation
   * could ensure that restarts or even re-installs would increment the counter based on previously
   * saved state in all circumstances. The easiest to implement is a random number.
   *
   * @param taskType Type of task, clarifies starting and reply message types
   * @param taskOptions Task options
   * @param future Future to be fired when task is successfully completed or exceptionally break
   *     when its failed
   * @return info bundle.
   */
  public synchronized RequestInfo createNextRequest(
      TaskType taskType, TaskOptions taskOptions, CompletableFuture<Void> future) {
    byte[] requestId = new byte[REQUEST_ID_SIZE];
    rnd.nextBytes(requestId);
    Bytes wrappedId = Bytes.wrap(requestId);
    if (taskOptions.isLivenessUpdate()) {
      future.whenComplete(
          (aVoid, throwable) -> {
            if (throwable == null) {
              updateLiveness();
            }
          });
    }
    RequestInfo requestInfo = RequestInfoFactory.create(taskType, wrappedId, taskOptions, future);
    requestIdStatuses.put(wrappedId, requestInfo);
    requestExpirationScheduler.put(
        wrappedId,
        new Runnable() {
          @Override
          public void run() {
            logger.debug(
                () ->
                    String.format(
                        "Request %s expired for id %s in session %s: no reply",
                        requestInfo, wrappedId, this));
            requestIdStatuses.remove(wrappedId);
          }
        });
    return requestInfo;
  }

  /** Updates request info. Thread-safe. */
  public synchronized void updateRequestInfo(Bytes requestId, RequestInfo newRequestInfo) {
    RequestInfo oldRequestInfo = requestIdStatuses.remove(requestId);
    if (oldRequestInfo == null) {
      logger.debug(
          () ->
              String.format(
                  "An attempt to update requestId %s in session %s which does not exist",
                  requestId, this));
      return;
    }
    requestIdStatuses.put(requestId, newRequestInfo);
    requestExpirationScheduler.put(
        requestId,
        new Runnable() {
          @Override
          public void run() {
            logger.debug(
                String.format(
                    "Request %s expired for id %s in session %s: no reply",
                    newRequestInfo, requestId, this));
            requestIdStatuses.remove(requestId);
          }
        });
  }

  public synchronized void cancelAllRequests(String message) {
    logger.debug(() -> String.format("Cancelling all requests in session %s", this));
    Set<Bytes> requestIdsCopy = new HashSet<>(requestIdStatuses.keySet());
    requestIdsCopy.forEach(
        requestId -> {
          RequestInfo requestInfo = clearRequestId(requestId);
          requestInfo
              .getFuture()
              .completeExceptionally(
                  new RuntimeException(
                      String.format(
                          "Request %s cancelled due to reason: %s", requestInfo, message)));
        });
  }

  /** Generates random nonce of {@link #NONCE_SIZE} size */
  public synchronized Bytes generateNonce() {
    byte[] nonce = new byte[NONCE_SIZE];
    rnd.nextBytes(nonce);
    return Bytes.wrap(nonce);
  }

  /** If true indicates that handshake is complete */
  public synchronized boolean isAuthenticated() {
    return SessionStatus.AUTHENTICATED.equals(status);
  }

  /** Resets stored authTags for this session making them obsolete */
  public void cleanup() {
    authTagRepo.expire(this);
  }

  public Optional<Bytes> getAuthTag() {
    return authTagRepo.getTag(this);
  }

  public void setAuthTag(Bytes authTag) {
    authTagRepo.put(authTag, this);
  }

  public Bytes getHomeNodeId() {
    return homeNodeId;
  }

  /** @return initiator key, also known as write key */
  public Bytes getInitiatorKey() {
    return initiatorKey;
  }

  public void setInitiatorKey(Bytes initiatorKey) {
    this.initiatorKey = initiatorKey;
  }

  /** @return recipient key, also known as read key */
  public Bytes getRecipientKey() {
    return recipientKey;
  }

  public void setRecipientKey(Bytes recipientKey) {
    this.recipientKey = recipientKey;
  }

  public Optional<InetSocketAddress> getReportedExternalAddress() {
    return reportedExternalAddress;
  }

  public void setReportedExternalAddress(final InetSocketAddress reportedExternalAddress) {
    this.reportedExternalAddress = Optional.of(reportedExternalAddress);
  }

  public synchronized void clearRequestId(Bytes requestId, TaskType taskType) {
    final RequestInfo requestInfo = clearRequestId(requestId);
    checkNotNull(requestInfo, "Attempting to clear an unknown request");
    checkArgument(
        taskType.equals(requestInfo.getTaskType()),
        "Attempting to clear a request but task type did not match");
    requestInfo.getFuture().complete(null);
  }

  /** Updates nodeRecord {@link NodeStatus} to ACTIVE of the node associated with this session */
  public synchronized void updateLiveness() {
    nodeRecord.ifPresent(
        record -> {
          NodeRecordInfo nodeRecordInfo =
              new NodeRecordInfo(record, Functions.getTime(), NodeStatus.ACTIVE, 0);
          nodeTable.save(nodeRecordInfo);
          nodeBucketStorage.put(nodeRecordInfo);
        });
  }

  private synchronized RequestInfo clearRequestId(Bytes requestId) {
    RequestInfo requestInfo = requestIdStatuses.remove(requestId);
    requestExpirationScheduler.cancel(requestId);
    return requestInfo;
  }

  public synchronized Optional<RequestInfo> getRequestId(Bytes requestId) {
    RequestInfo requestInfo = requestIdStatuses.get(requestId);
    return requestId == null ? Optional.empty() : Optional.of(requestInfo);
  }

  /**
   * Returns any queued {@link RequestInfo} which was not started because session is not
   * authenticated
   */
  public synchronized Optional<RequestInfo> getFirstAwaitRequestInfo() {
    return requestIdStatuses.values().stream()
            .filter(requestInfo -> AWAIT.equals(requestInfo.getTaskStatus()))
            .findFirst();
  }
  public synchronized Optional<RequestInfo> getFirstSentRequestInfo() {
    return requestIdStatuses.values().stream()
            .filter(requestInfo -> SENT.equals(requestInfo.getTaskStatus()))
            .findFirst();
  }

  public NodeTable getNodeTable() {
    return nodeTable;
  }

  public void putRecordInBucket(NodeRecordInfo nodeRecordInfo) {
    nodeBucketStorage.put(nodeRecordInfo);
  }

  public Optional<NodeBucket> getBucket(int index) {
    return nodeBucketStorage.get(index);
  }

  public synchronized Bytes getIdNonce() {
    return idNonce;
  }

  public synchronized void setIdNonce(Bytes idNonce) {
    this.idNonce = idNonce;
  }

  public NodeRecord getHomeNodeRecord() {
    return localNodeRecordStore.getLocalNodeRecord();
  }

  @Override
  public String toString() {
    return "NodeSession{" + nodeId + " (" + status + ")}";
  }

  public synchronized SessionStatus getStatus() {
    return status;
  }

  public synchronized void setStatus(SessionStatus newStatus) {
    logger.debug(
        () ->
            String.format("Switching status of node %s from %s to %s", nodeId, status, newStatus));
    this.status = newStatus;
  }

  public Bytes getStaticNodeKey() {
    return staticNodeKey;
  }

  public enum SessionStatus {
    INITIAL, // other side is trying to connect, or we are initiating (before random packet is sent
    WHOAREYOU_SENT, // other side is initiator, we've sent whoareyou in response
    RANDOM_PACKET_SENT, // our node is initiator, we've sent random packet
    AUTHENTICATED
  }
}
