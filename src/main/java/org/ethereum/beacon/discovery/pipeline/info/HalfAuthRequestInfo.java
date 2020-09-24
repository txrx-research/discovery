/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline.info;

import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.packet.AuthHeaderMessagePacket;
import org.ethereum.beacon.discovery.task.TaskStatus;
import org.ethereum.beacon.discovery.task.TaskType;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

public class HalfAuthRequestInfo implements RequestInfo {
  private final TaskType taskType;
  private final TaskStatus taskStatus;
  private final Bytes requestId;
  private Bytes authTag = null;
  private final CompletableFuture<Void> future;
  private Consumer<AuthHeaderMessagePacket> authCallback = null;

  public HalfAuthRequestInfo(
      TaskType taskType, TaskStatus taskStatus, Bytes requestId,CompletableFuture<Void> future) {
    this.taskType = taskType;
    this.taskStatus = taskStatus;
    this.requestId = requestId;
    this.future = future;
  }

  public HalfAuthRequestInfo(TaskType taskType, TaskStatus taskStatus, Bytes requestId, Bytes authTag, CompletableFuture<Void> future, Consumer<AuthHeaderMessagePacket> authCallback) {
    this.taskType = taskType;
    this.taskStatus = taskStatus;
    this.requestId = requestId;
    this.authTag = authTag;
    this.future = future;
    this.authCallback = authCallback;
  }

  @Override
  public TaskType getTaskType() {
    return taskType;
  }

  @Override
  public TaskStatus getTaskStatus() {
    return taskStatus;
  }

  @Override
  public Bytes getRequestId() {
    return requestId;
  }

  public Bytes getAuthTag() {
    return authTag;
  }

  public void setAuthTag(Bytes authTag) {
    this.authTag = authTag;
  }

  @Override
  public CompletableFuture<Void> getFuture() {
    return future;
  }

  public Consumer<AuthHeaderMessagePacket> getAuthCallback() {
    return authCallback;
  }

  @Override
  public RequestInfo withStatus(final TaskStatus status) {
    return new HalfAuthRequestInfo(getTaskType(), status, getRequestId(), getAuthTag(), getFuture(), getAuthCallback());
  }

  @Override
  public String toString() {
    return "GeneralRequestInfo{"
        + "taskType="
        + taskType
        + ", taskStatus="
        + taskStatus
        + ", requestId="
        + requestId
        + '}';
  }
}
