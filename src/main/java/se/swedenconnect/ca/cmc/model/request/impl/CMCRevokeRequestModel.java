/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.ca.cmc.model.request.impl;

import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;

import lombok.Getter;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * CMC Revocation request model.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CMCRevokeRequestModel extends AbstractCMCRequestModel {

  /** Issuer name */
  private final X500Name issuerName;

  /** Serial number */
  private final BigInteger serialNumber;

  /** Reason code */
  private final int reason;

  /** Revocation time */
  private final Date revocationDate;

  /**
   * Constructor.
   *
   * @param serialNumber serial number
   * @param reason reason code
   * @param revocationDate revocation time
   * @param issuerName issuer name
   */
  public CMCRevokeRequestModel(
      final BigInteger serialNumber, final int reason, final Date revocationDate, final X500Name issuerName) {
    super(CMCRequestType.revoke);
    this.serialNumber = serialNumber;
    this.reason = reason;
    this.revocationDate = revocationDate;
    this.issuerName = issuerName;
  }
}
