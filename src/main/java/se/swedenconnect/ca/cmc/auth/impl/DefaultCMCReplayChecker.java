/*
 * Copyright 2023 Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.ca.cmc.auth.impl;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.cms.CMSSignedData;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.auth.CMCReplayChecker;
import se.swedenconnect.ca.cmc.auth.CMCReplayException;
import se.swedenconnect.ca.cmc.auth.CMCUtils;

/**
 * Default implementation of a replay checker.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultCMCReplayChecker implements CMCReplayChecker {

  private static final Date startupTime;

  static {
    final RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
    startupTime = new Date(runtimeMXBean.getStartTime());
  }

  private List<ReplayData> nonceList = new ArrayList<>();
  long maxAgeMillis;
  long retentionMillis;
  long futureTimeSkewMillis;

  /**
   * Constructor.
   *
   * @param maxAgeSec the maximum age in seconds allowed for CMC requests before they are discarded for being too old
   * @param retentionSec the maximum time information about a processed CMC request is stored for replay checking
   * @param futureTimeSkewSec the maximum time skew allowed between requester and responder
   */
  public DefaultCMCReplayChecker(final int maxAgeSec, final long retentionSec, final long futureTimeSkewSec) {
    this.maxAgeMillis = 1000L * maxAgeSec;
    this.retentionMillis = 1000L * retentionSec;
    this.futureTimeSkewMillis = 1000L * futureTimeSkewSec;
    log.info(
        "Replay checker created with system start time = {}, max age sec={}, retention sec={}, future time skew sec={}",
        startupTime, maxAgeSec, retentionSec, futureTimeSkewSec);
  }

  /**
   * Constructor with fixed max skew time set to 60 seconds
   *
   * @param maxAgeSec the maximum age in seconds allowed for CMC requests before they are discarded for being too old
   * @param retentionSec the maximum time information about a processed CMC request is stored for replay checking
   */
  public DefaultCMCReplayChecker(final int maxAgeSec, final long retentionSec) {
    this(maxAgeSec, retentionSec, 60);
  }

  /**
   * Constructor with default values (Max age = 120 sec, Retention = 200 sec and time skew = 60 sec)
   */
  public DefaultCMCReplayChecker() {
    this(120, 200, 60);
  }

  @Override
  public void validate(final CMSSignedData signedData) throws CMCReplayException {
    try {
      this.consolidateReplayData();
      final PKIData pkiData;
      try (final ASN1InputStream as = new ASN1InputStream((byte[]) signedData.getSignedContent().getContent())) {
        pkiData = PKIData.getInstance(as.readObject());
      }
      final Date messageTime = CMCUtils.getSigningTime(signedData);
      final Date notBefore = new Date(System.currentTimeMillis() - this.maxAgeMillis);
      final Date notAfter = new Date(System.currentTimeMillis() + this.futureTimeSkewMillis);
      if (messageTime == null) {
        throw new CMCReplayException("Replay check failed: Message time is missing in CMC request");
      }
      if (messageTime.before(startupTime)) {
        // We do not allow under any circumstances a message created before startup time as we have no knowledge of what
        // happened before this instant.
        throw new CMCReplayException("Replay check failed: Request older than system startup time");
      }
      if (messageTime.before(notBefore)) {
        throw new CMCReplayException("Replay check failed: Request is to lod");
      }
      if (messageTime.after(notAfter)) {
        throw new CMCReplayException("Replay check failed: Request time in future time");
      }
      final byte[] nonce =
          (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_senderNonce, pkiData).getValue();
      if (nonce == null) {
        throw new CMCReplayException("Replay check failed: Request nonce is missing");
      }

      if (this.nonceList.stream().anyMatch(replayData -> Arrays.equals(nonce, replayData.getNonce()))) {
        throw new CMCReplayException("Replay check failed: Replay of request nonce");
      }
      this.nonceList.add(new ReplayData(nonce, messageTime));
    }
    catch (final Exception e) {
      if (e instanceof CMCReplayException) {
        throw (CMCReplayException) e;
      }
      throw new CMCReplayException("Error processing replay data - Replay check failed", e);
    }
  }

  private void consolidateReplayData() {
    final Date maxAge = new Date(System.currentTimeMillis() - this.retentionMillis);
    this.nonceList = this.nonceList.stream()
        .filter(replayData -> replayData.getMessageTime().after(maxAge))
        .collect(Collectors.toList());
  }

  /**
   * Data class for holding replay data for replay tests on CMC requests
   */
  @Getter
  @AllArgsConstructor
  public static class ReplayData {
    /** the nonce value of the CMC request */
    byte[] nonce;
    /** the time the CMC request with this nonce was processed */
    Date messageTime;
  }

}
