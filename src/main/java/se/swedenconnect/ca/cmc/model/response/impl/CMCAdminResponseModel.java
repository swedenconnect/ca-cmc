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
package se.swedenconnect.ca.cmc.model.response.impl;

import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.Getter;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * Response model for creating CMC responses for Admin requests
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCAdminResponseModel extends AbstractCMCResponseModel {

  /** Admin CMC data */
  @Getter
  private final AdminCMCData adminCMCData;

  /**
   * Constructor.
   *
   * @param nonce response nonce
   * @param cmcResponseStatus response status
   * @param cmcRequestType request type
   * @param adminCMCData custom admin response data
   * @throws CMCMessageException errors parsing admin response data
   */
  public CMCAdminResponseModel(final byte[] nonce, final CMCResponseStatus cmcResponseStatus,
      final CMCRequestType cmcRequestType, final AdminCMCData adminCMCData) throws CMCMessageException {
    super(nonce, cmcResponseStatus, cmcRequestType, getResponseInfo(adminCMCData));
    this.adminCMCData = adminCMCData;
  }

  private static byte[] getResponseInfo(final AdminCMCData adminCMCData) throws CMCMessageException {
    try {
      return CMCUtils.OBJECT_MAPPER.writeValueAsBytes(adminCMCData);
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Unable to convert admin request data to JSON", e);
    }
  }

}
