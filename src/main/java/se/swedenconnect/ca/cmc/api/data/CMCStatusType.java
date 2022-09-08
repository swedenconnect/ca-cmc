/*
 * Copyright 2021-2022 Agency for Digital Government (DIGG)
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
package se.swedenconnect.ca.cmc.api.data;

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmc.CMCStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * Enumeration of status type
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
@Getter
@Slf4j
public enum CMCStatusType {

  /** Success */
  success(CMCStatus.success, 0),

  /** Failed */
  failed(CMCStatus.failed, 2),

  /** Pending */
  pending(CMCStatus.pending, 3),

  /** Option not supported */
  noSupport(CMCStatus.noSupport, 4),

  /** Request must be confirmed */
  confirmRequired(CMCStatus.confirmRequired, 5),

  /** Proof-of-possession of private key is missing */
  popRequired(CMCStatus.popRequired, 6),

  /** Some data is missing to complete the request */
  partial(CMCStatus.partial, 7);

  private CMCStatus cmcStatus;
  private int value;

  /**
   * Get CMCStatus from integer value
   *
   * @param value the integer value of a CMC Status according to RFC 5272
   * @return {@link CMCStatusType}
   */
  public static CMCStatusType getCMCStatusType(final int value) {
    return Arrays.stream(values())
        .filter(cmcStatusType -> cmcStatusType.getValue() == value)
        .findFirst()
        .orElse(null);
  }

  /**
   * Get CMCStatus from CMCStatus value
   *
   * @param cmcStatus CMCStatus value
   * @return {@link CMCStatusType}
   */
  public static CMCStatusType getCMCStatusType(final CMCStatus cmcStatus) {
    try {
      int intVal = ((ASN1Integer) cmcStatus.toASN1Primitive()).intPositiveValueExact();
      return getCMCStatusType(intVal);
    }
    catch (Exception ex) {
      log.debug("Bad CMCStatus syntax", ex);
      return null;
    }
  }

}
