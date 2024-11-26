/*
 * Copyright 2024 Agency for Digital Government (DIGG)
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
package se.swedenconnect.ca.cmc.model.response.impl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;

/**
 * Abstract implementation of the CMC response model.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AbstractCMCResponseModel implements CMCResponseModel {

  /**
   * Nonce
   *
   * @param nonce nonce
   * @return nonce value
   */
  @Getter
  @Setter
  protected byte[] nonce;

  /**
   * Response info bytes used to communicate custom result data in the response
   *
   * @param responseInfo response info
   * @return response info bytes
   */
  @Getter
  @Setter
  protected byte[] responseInfo;

  /**
   * Certificates returned by the CMC response
   *
   * @param returnCertificates return certificates
   * @return certificates returned in CMC response
   */
  @Getter
  @Setter
  protected List<X509Certificate> returnCertificates;

  /**
   * Status of the CMC response
   *
   * @return cmc response status
   */
  @Getter
  protected CMCResponseStatus cmcResponseStatus;

  /**
   * CMC Request type
   *
   * @return cmc request type
   */
  @Getter
  protected CMCRequestType cmcRequestType;

  /**
   * Constructor for response model with no custom data.
   *
   * @param nonce response nonce
   * @param cmcResponseStatus response status
   * @param cmcRequestType request type
   */
  public AbstractCMCResponseModel(
      final byte[] nonce, final CMCResponseStatus cmcResponseStatus, final CMCRequestType cmcRequestType) {
    this(nonce, cmcResponseStatus, cmcRequestType, null);
  }

  /**
   * Constructor for response model with custom data.
   *
   * @param nonce response nonce
   * @param cmcResponseStatus response status
   * @param cmcRequestType request type
   * @param responseInfo custom response data
   */
  public AbstractCMCResponseModel(final byte[] nonce, final CMCResponseStatus cmcResponseStatus,
      final CMCRequestType cmcRequestType, final byte[] responseInfo) {
    this.nonce = nonce;
    this.responseInfo = responseInfo;
    this.cmcResponseStatus = cmcResponseStatus;
    this.returnCertificates = new ArrayList<>();
    this.cmcRequestType = cmcRequestType;
  }

}
