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
package se.swedenconnect.ca.cmc.api;

import java.util.List;

import org.bouncycastle.asn1.cmc.BodyPartID;

import lombok.Getter;
import se.swedenconnect.ca.cmc.CMCException;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;

/**
 * Exception used within the CMC CA API.
 *
 * This exception provides information about the CMC failure code as well as a list of body part IDs of CMC objects that
 * caused the failure.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCCaApiException extends CMCException {

  private static final long serialVersionUID = -887662559964395201L;

  /** List of BodyPartID of CMC objects that was processed when the failure occurred */
  @Getter
  private final List<BodyPartID> failingBodyPartIds;

  /** CMC failure type */
  @Getter
  private final CMCFailType cmcFailType;

  /**
   * Constructor
   *
   * @param message message
   * @param failingBodyPartIds failing body part IDs
   * @param cmcFailType cmc fail type
   */
  public CMCCaApiException(
      final String message, final List<BodyPartID> failingBodyPartIds, final CMCFailType cmcFailType) {
    super(message);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   * @param failingBodyPartIds failing body part IDs
   * @param cmcFailType cmc fail type
   */
  public CMCCaApiException(final String message, final Throwable cause,
      final List<BodyPartID> failingBodyPartIds, final CMCFailType cmcFailType) {
    super(message, cause);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }

  /**
   * Constructor
   *
   * @param cause cause
   * @param failingBodyPartIds failing body part IDs
   * @param cmcFailType cmc fail type
   */
  public CMCCaApiException(
      final Throwable cause, final List<BodyPartID> failingBodyPartIds, final CMCFailType cmcFailType) {
    super(cause);
    this.failingBodyPartIds = failingBodyPartIds;
    this.cmcFailType = cmcFailType;
  }
}
