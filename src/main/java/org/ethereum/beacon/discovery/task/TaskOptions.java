/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.task;

import org.ethereum.beacon.discovery.packet.AuthHeaderMessagePacket;

import java.util.function.Consumer;

/** Specific options to clarify task features */
public class TaskOptions {
  private boolean livenessUpdate;
  private int distance;
  private Consumer<AuthHeaderMessagePacket> authCallback = null;
  private AuthHeaderMessagePacket authHeaderMessagePacket = null;

  public TaskOptions(boolean livenessUpdate) {
    this.livenessUpdate = livenessUpdate;
  }

  public TaskOptions(boolean livenessUpdate, int distance) {
    this.livenessUpdate = livenessUpdate;
    this.distance = distance;
  }
  public TaskOptions(Consumer<AuthHeaderMessagePacket> authCallback) {
    this.authCallback = authCallback;
  }

  public TaskOptions(AuthHeaderMessagePacket authHeaderMessagePacket) {
    this.authHeaderMessagePacket = authHeaderMessagePacket;
  }

  public boolean isLivenessUpdate() {
    return livenessUpdate;
  }

  public int getDistance() {
    return distance;
  }

  public Consumer<AuthHeaderMessagePacket> getAuthCallback() {
    return authCallback;
  }

  public AuthHeaderMessagePacket getAuthHeaderMessagePacket() {
    return authHeaderMessagePacket;
  }
}
