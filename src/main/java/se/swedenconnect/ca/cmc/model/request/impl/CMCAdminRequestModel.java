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

import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.Getter;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * CMC Revocation request model.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class CMCAdminRequestModel extends AbstractCMCRequestModel {

  /**
   * Constructor for CMC admin request model.
   *
   * @param adminRequestData admin request data
   * @throws CMCMessageException on errors parsing admin request data
   */
  public CMCAdminRequestModel(final AdminCMCData adminRequestData) throws CMCMessageException {
    super(CMCRequestType.admin, getReqInfo(adminRequestData));
  }

  /**
   * Get the JSON byte representation of the admin request data
   *
   * @param adminCMCData admin request data
   * @return bytes of the admin request data
   * @throws CMCMessageException on errors parsing admin request data
   */
  private static byte[] getReqInfo(final AdminCMCData adminCMCData) throws CMCMessageException {
    try {
      return CMCUtils.OBJECT_MAPPER.writeValueAsBytes(adminCMCData);
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Unable to convert admin request data to JSON", e);
    }
  }
}
