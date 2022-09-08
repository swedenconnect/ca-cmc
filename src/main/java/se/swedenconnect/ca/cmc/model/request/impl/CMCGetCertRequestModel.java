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
package se.swedenconnect.ca.cmc.model.request.impl;

import java.math.BigInteger;

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
public class CMCGetCertRequestModel extends AbstractCMCRequestModel {

  private final X500Name issuerName;
  private final BigInteger serialNumber;

  /**
   * Constructor.
   *
   * @param serialNumber serial number of certificate to revoke
   * @param issuerName issuer name of the certificate issuer
   */
  public CMCGetCertRequestModel(final BigInteger serialNumber, final X500Name issuerName) {
    super(CMCRequestType.getCert);
    this.serialNumber = serialNumber;
    this.issuerName = issuerName;
  }

}
