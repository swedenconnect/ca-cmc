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
package se.swedenconnect.ca.cmc.api.client;

import java.util.List;

import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.CertificateData;
import se.swedenconnect.ca.cmc.model.admin.response.StaticCAInformation;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * Providing a set of static CMC response data extraction functions.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCResponseExtract {

  /** JSON object mapper */
  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  /**
   * Obtain admin CMC data from a CMC response
   *
   * @param cmcResponse CMC response
   * @return {@link AdminCMCData}
   * @throws CMCMessageException error parsing CMC response
   */
  public static AdminCMCData getAdminCMCData(final CMCResponse cmcResponse) throws CMCMessageException {
    if (!cmcResponse.getCmcRequestType().equals(CMCRequestType.admin)) {
      throw new CMCMessageException("Not an admin response");
    }
    final CMCControlObject cmcControlObject =
        CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_responseInfo, cmcResponse.getPkiResponse());
    final AdminCMCData adminCMCData = (AdminCMCData) cmcControlObject.getValue();
    return adminCMCData;
  }

  /**
   * Extract certificate data from a CMC response
   *
   * @param cmcResponse CMC response
   * @return list of certificate data
   * @throws CMCMessageException error parsing CMC response
   */
  public static List<CertificateData> extractCertificateData(final CMCResponse cmcResponse) throws CMCMessageException {
    try {
      final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
      if (!adminCMCData.getAdminRequestType().equals(AdminRequestType.listCerts)) {
        throw new CMCMessageException("Not a list certificates response");
      }
      final List<CertificateData> certificateDataList =
          OBJECT_MAPPER.readValue(adminCMCData.getData(), new TypeReference<>() {
          });
      return certificateDataList;
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to extract certificate data", e);
    }
  }

  /**
   * Extract CA information from a CMC Response
   *
   * @param cmcResponse CMC response
   * @return {@link CAInformation}
   * @throws CMCMessageException error parsing the CMC response
   */
  public static CAInformation extractCAInformation(final CMCResponse cmcResponse) throws CMCMessageException {
    try {
      final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
      if (!adminCMCData.getAdminRequestType().equals(AdminRequestType.caInfo)) {
        throw new CMCMessageException("Not a CA information response");
      }
      final CAInformation caInformation = OBJECT_MAPPER.readValue(adminCMCData.getData(), CAInformation.class);
      return caInformation;
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to extract CA information from CMC response", e);
    }
  }

  /**
   * Extract static CA information from a CMC Response
   *
   * @param cmcResponse CMC response
   * @return {@link CAInformation}
   * @throws CMCMessageException error parsing the CMC response
   */
  public static StaticCAInformation extractStaticCAInformation(final CMCResponse cmcResponse)
      throws CMCMessageException {
    try {
      final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
      if (!adminCMCData.getAdminRequestType().equals(AdminRequestType.staticCaInfo)) {
        throw new CMCMessageException("Not a static CA information response");
      }
      final StaticCAInformation caInformation =
          OBJECT_MAPPER.readValue(adminCMCData.getData(), StaticCAInformation.class);
      return caInformation;
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to extract static CA information from CMC response", e);
    }
  }

}
