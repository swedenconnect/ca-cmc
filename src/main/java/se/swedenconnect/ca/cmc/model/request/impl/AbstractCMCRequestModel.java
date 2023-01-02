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
package se.swedenconnect.ca.cmc.model.request.impl;

import java.security.SecureRandom;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * Abstract implementation of the CMC request model holding metadata of a CMC request.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractCMCRequestModel implements CMCRequestModel {

  /** Secure random generator */
  private static final SecureRandom RNG = CMCUtils.RNG;

  /**
   * Gets the request nonce
   *
   * @param nonce request nonce
   * @return request nonce
   */
  @Getter
  @Setter
  protected byte[] nonce;

  /**
   * The registration info data. This parameter is generally used to pass custom request data. Each request type
   * identifies the syntax of this parameter
   *
   * @param registrationInfo registration info data
   * @return registration info data
   */
  @Getter
  @Setter
  protected byte[] registrationInfo;

  /**
   * The type of request
   *
   * @return CMC request type
   */
  @Getter
  protected CMCRequestType cmcRequestType;

  /**
   * Constructor setting the CMC request type.
   *
   * @param cmcRequestType CMC request type
   */
  public AbstractCMCRequestModel(final CMCRequestType cmcRequestType) {
    this(cmcRequestType, null);
  }

  /**
   * Constructor setting CMC request type and registration info
   *
   * @param cmcRequestType CMC request type
   * @param registrationInfo registration info
   */
  public AbstractCMCRequestModel(final CMCRequestType cmcRequestType, final byte[] registrationInfo) {
    this.registrationInfo = registrationInfo;
    this.cmcRequestType = cmcRequestType;
    this.nonce = new byte[128];
    RNG.nextBytes(this.nonce);
  }

}
