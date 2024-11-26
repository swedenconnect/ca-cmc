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
package se.swedenconnect.ca.cmc.api.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;

import se.swedenconnect.ca.cmc.CMCException;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.request.ListCerts;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.CertificateData;
import se.swedenconnect.ca.cmc.model.admin.response.StaticCAInformation;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;

/**
 * The default admin implementation of the CMC CA API. This implementation extends the AbstractCMCCaApi which provides
 * the basic CMC API features. This implementation extends this with a default implementation of a handler of admin API
 * requests.
 *
 * <p>
 * Note that the admin CMC requests are using a custom protocol structure adding to standardized CMC using generic data
 * transfer. A CMC API that does not implement the admin features would directly implement the AbstractCMCCaApi class.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractAdminCMCCaApi extends AbstractCMCCaApi {

  /**
   * Constructor
   *
   * @param caService the CA service providing CA service operations
   * @param cmcRequestParser parser for parsing CMC requests
   * @param cmcResponseFactory factory for creating CMC responses
   */
  public AbstractAdminCMCCaApi(final CAService caService,
      final CMCRequestParser cmcRequestParser, final CMCResponseFactory cmcResponseFactory) {
    super(caService, cmcRequestParser, cmcResponseFactory);
  }

  /** {@inheritDoc} */
  @Override
  protected AdminCMCData getAdminResponse(final AdminCMCData adminRequest) throws CMCException {

    final AdminRequestType adminRequestType = adminRequest.getAdminRequestType();
    String responseInfo = null;

    switch (adminRequestType) {
    case caInfo:
      responseInfo = this.getCAInfoResponse();
      break;
    case staticCaInfo:
      responseInfo = this.getStaticCAInfoResponse();
      break;
    case listCerts:
      final ListCerts listCertsRequest;
      try {
        listCertsRequest = CMCUtils.OBJECT_MAPPER.readValue(adminRequest.getData(), ListCerts.class);
      }
      catch (final JsonProcessingException e) {
        throw new CMCMessageException("Failed to get list certs", e);
      }
      responseInfo = this.getListCertsResponse(listCertsRequest);
      break;
    case allCertSerials:
      responseInfo = this.getAllCertSerials();
      break;
    }

    return AdminCMCData.builder()
        .adminRequestType(adminRequestType)
        .data(responseInfo)
        .build();
  }

  private String getAllCertSerials() throws CMCMessageException {
    final List<BigInteger> allCertificates = this.caService.getCaRepository().getAllCertificates();
    final List<String> allCertSerialStrings = allCertificates.stream()
        .map(bigInteger -> bigInteger.toString(16))
        .collect(Collectors.toList());
    try {
      return CMCUtils.OBJECT_MAPPER.writeValueAsString(allCertSerialStrings);
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to get all cert serials", e);
    }
  }

  private String getListCertsResponse(final ListCerts listCertsReqeust) throws CMCMessageException {
    final CARepository caRepository = this.caService.getCaRepository();
    final List<CertificateRecord> certificateRange = caRepository.getCertificateRange(
        listCertsReqeust.getPageIndex(),
        listCertsReqeust.getPageSize(),
        listCertsReqeust.isNotRevoked(),
        listCertsReqeust.getSortBy(),
        listCertsReqeust.isDescending());

    final List<CertificateData> certificateDataList = new ArrayList<>();
    for (final CertificateRecord certificateRecord : certificateRange) {
      final CertificateData.CertificateDataBuilder builder = CertificateData.builder()
          .certificate(certificateRecord.getCertificate())
          .revoked(certificateRecord.isRevoked());

      if (certificateRecord.isRevoked()) {
        builder
            .revocationReason(certificateRecord.getReason())
            .revocationDate(certificateRecord.getRevocationTime().getTime());
      }
      certificateDataList.add(builder.build());
    }
    try {
      return CMCUtils.OBJECT_MAPPER.writeValueAsString(certificateDataList);
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to create list certs response", e);
    }
  }

  private String getCAInfoResponse() throws CMCMessageException {
    try {
      final CARepository caRepository = this.caService.getCaRepository();
      final CAInformation caInformation = CAInformation.builder()
          .validCertificateCount(caRepository.getCertificateCount(true))
          .certificateCount(caRepository.getCertificateCount(false))
          .certificateChain(CMCUtils.getCerHolderByteList(this.caService.getCACertificateChain()))
          .ocspCertificate(this.caService.getOCSPResponderCertificate() != null
              ? this.caService.getOCSPResponderCertificate().getEncoded()
              : null)
          .caAlgorithm(this.caService.getCaAlgorithm())
          .ocspResponserUrl(this.caService.getOCSPResponderURL())
          .crlDpURLs(this.caService.getCrlDpURLs())
          .build();
      return CMCUtils.OBJECT_MAPPER.writeValueAsString(caInformation);
    }
    catch (final IOException | CertificateException e) {
      throw new CMCMessageException("Failed to create CA info response", e);
    }
  }

  private String getStaticCAInfoResponse() throws CMCMessageException {
    try {
      final StaticCAInformation caInformation = StaticCAInformation.builder()
          .certificateChain(CMCUtils.getCerHolderByteList(this.caService.getCACertificateChain()))
          .ocspCertificate(this.caService.getOCSPResponderCertificate() != null
              ? this.caService.getOCSPResponderCertificate().getEncoded()
              : null)
          .caAlgorithm(this.caService.getCaAlgorithm())
          .ocspResponserUrl(this.caService.getOCSPResponderURL())
          .crlDpURLs(this.caService.getCrlDpURLs())
          .build();
      return CMCUtils.OBJECT_MAPPER.writeValueAsString(caInformation);
    }
    catch (final IOException | CertificateException e) {
      throw new CMCMessageException("Failed to create static CA info response", e);
    }
  }

}
