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
package se.swedenconnect.ca.cmc.api.impl;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.GetCert;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.RevokeRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.CMCException;
import se.swedenconnect.ca.cmc.api.CMCCaApi;
import se.swedenconnect.ca.cmc.api.CMCCaApiException;
import se.swedenconnect.ca.cmc.api.CMCParsingException;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;
import se.swedenconnect.ca.cmc.model.response.impl.CMCAdminResponseModel;
import se.swedenconnect.ca.cmc.model.response.impl.CMCBasicCMCResponseModel;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.utils.CAUtils;

/**
 * Abstract CMC CA API implementation implementing the functions of a CA service serving requests for service received
 * in the form of a CMC request.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractCMCCaApi implements CMCCaApi {

  /** CA service performing requested CA operations */
  protected final CAService caService;

  /** Request parser used to parse CMC requests */
  protected final CMCRequestParser cmcRequestParser;

  /** Factory for constructing CMC responses */
  protected final CMCResponseFactory cmcResponseFactory;

  /**
   * Constructor
   *
   * @param caService the CA service providing CA service operations
   * @param cmcRequestParser parser for parsing CMC requests
   * @param cmcResponseFactory factory for creating CMC responses
   */
  public AbstractCMCCaApi(final CAService caService, final CMCRequestParser cmcRequestParser,
      final CMCResponseFactory cmcResponseFactory) {
    this.caService = caService;
    this.cmcRequestParser = cmcRequestParser;
    this.cmcResponseFactory = cmcResponseFactory;
  }

  /** {@inheritDoc} */
  @Override
  public CMCResponse processRequest(final byte[] cmcRequestBytes) {

    byte[] nonce = new byte[] {};

    try {
      final CMCRequest cmcRequest = this.cmcRequestParser.parseCMCrequest(cmcRequestBytes);
      nonce = cmcRequest.getNonce();
      final CMCRequestType cmcRequestType = cmcRequest.getCmcRequestType();
      switch (cmcRequestType) {

      case issueCert:
        return this.processCertIssuingRequest(cmcRequest);
      case revoke:
        return this.processRevokeRequest(cmcRequest);
      case admin:
        return this.processCustomRequest(cmcRequest);
      case getCert:
        return this.processGetCertRequest(cmcRequest);
      default:
        throw new IllegalArgumentException("Unrecognized CMC request type");
      }
    }
    catch (final Exception ex) {
      try {
        if (ex instanceof CMCParsingException) {
          final CMCParsingException cmcParsingException = (CMCParsingException) ex;
          final CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
              cmcParsingException.getNonce(),
              CMCResponseStatus.builder()
                  .status(CMCStatusType.failed)
                  .failType(CMCFailType.badRequest)
                  .message(ex.getMessage())
                  .bodyPartIDList(new ArrayList<>())
                  .build(),
              null, null);
          return this.cmcResponseFactory.getCMCResponse(responseModel);
        }
        if (ex instanceof CMCCaApiException) {
          // Processing CMC request resulted in a error exception.
          final CMCCaApiException cmcException = (CMCCaApiException) ex;
          final CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
              nonce,
              CMCResponseStatus.builder()
                  .status(CMCStatusType.failed)
                  .failType(cmcException.getCmcFailType())
                  .message(ex.getMessage())
                  .bodyPartIDList(cmcException.getFailingBodyPartIds())
                  .build(),

              null, null);
          return this.cmcResponseFactory.getCMCResponse(responseModel);
        }
        else {
          // Processing CMC request resulted in a general exception caused by internal CA error.
          final CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
              nonce,
              CMCResponseStatus.builder()
                  .status(CMCStatusType.failed)
                  .failType(CMCFailType.internalCAError)
                  .message(ex.getMessage())
                  .bodyPartIDList(new ArrayList<>())
                  .build(),

              null, null);
          return this.cmcResponseFactory.getCMCResponse(responseModel);
        }
      }
      catch (final Exception e) {
        // This should never happen unless there is a serious bug or configuration error
        // The exception caught here is related to parsing returnCertificates which is passed as a null parameter in
        // this case
        log.error("Critical exception in CA API implementation", e);
        throw new RuntimeException("Critical exception in CA API implementation", e);
      }
    }
  }

  /**
   * Process certificate issuing request
   *
   * @param cmcRequest CMC request
   * @return CMC response
   * @throws CMCCaApiException error parsing the certificate issuing request
   */
  protected CMCResponse processCertIssuingRequest(final CMCRequest cmcRequest) throws CMCCaApiException {

    try {
      final CertificateModel certificateModel = this.getCertificateModel(cmcRequest);
      final X509CertificateHolder certificateHolder = this.caService.issueCertificate(certificateModel);

      final CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
          cmcRequest.getNonce(),
          new CMCResponseStatus(CMCStatusType.success, Arrays.asList(cmcRequest.getCertReqBodyPartId())),
          cmcRequest.getCmcRequestType(),
          (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, cmcRequest.getPkiData())
              .getValue(),
          Arrays.asList(certificateHolder));

      return this.cmcResponseFactory.getCMCResponse(responseModel);
    }
    catch (final Exception ex) {
      final List<BodyPartID> failingBodyPartIds = cmcRequest.getCertReqBodyPartId() == null
          ? new ArrayList<>()
          : Arrays.asList(cmcRequest.getCertReqBodyPartId());
      throw new CMCCaApiException(ex, failingBodyPartIds, CMCFailType.badRequest);
    }
  }

  /**
   * This functions generates a certificate request model from the certificate request and control parameters from a CMC
   * request
   *
   * @param cmcRequest CMC Request
   * @return certificate model
   * @throws CMCException any exception caught while attempting to create a certificate model from the CMC request
   */
  abstract CertificateModel getCertificateModel(CMCRequest cmcRequest) throws CMCException;

  /**
   * Process a request to revoke a certificate
   *
   * @param cmcRequest CMC request
   * @return CMC response
   * @throws CMCCaApiException error parsing the revocation request
   */
  protected CMCResponse processRevokeRequest(final CMCRequest cmcRequest) throws CMCCaApiException {
    try {
      final PKIData pkiData = cmcRequest.getPkiData();
      final CMCControlObject cmcControlObject =
          CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest, pkiData);
      final BodyPartID revokeBodyPartId = cmcControlObject.getBodyPartID();
      final RevokeRequest revokeRequest = (RevokeRequest) cmcControlObject.getValue();
      // Check issuer name
      final X500Name issuerName = revokeRequest.getName();
      if (this.caService.getCaCertificate().getSubject().equals(issuerName)) {
        final Date revokeDate = revokeRequest.getInvalidityDate().getDate();
        final int reason = revokeRequest.getReason().getValue().intValue();
        final BigInteger serialNumber = revokeRequest.getSerialNumber();

        try {
          this.caService.revokeCertificate(serialNumber, reason, revokeDate);
          this.caService.publishNewCrl();
        }
        catch (final Exception ex2) {
          throw new CMCCaApiException(ex2.getMessage(), ex2, Arrays.asList(revokeBodyPartId), CMCFailType.badCertId);
        }
        final CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
            cmcRequest.getNonce(),
            new CMCResponseStatus(CMCStatusType.success, Arrays.asList(revokeBodyPartId)), null, null);
        return this.cmcResponseFactory.getCMCResponse(responseModel);
      }
      else {
        throw new CMCCaApiException("Revocation request does not match CA issuer name", Arrays.asList(revokeBodyPartId),
            CMCFailType.badRequest);
      }
    }
    catch (final Exception ex) {
      if (ex instanceof CMCCaApiException) {
        throw (CMCCaApiException) ex;
      }
      throw new CMCCaApiException(ex, new ArrayList<>(), CMCFailType.badRequest);
    }
  }

  /**
   * Process a custom request that adds to the standard CMC API by passing request data in the CMC request info byte
   * array.
   *
   * @param cmcRequest CMC request
   * @return CMC response
   * @throws CMCException error parsing this as a valid custom request
   */
  protected CMCResponse processCustomRequest(final CMCRequest cmcRequest) throws CMCException {
    final PKIData pkiData = cmcRequest.getPkiData();
    final CMCControlObject cmcControlObject =
        CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, pkiData);
    final AdminCMCData adminRequest = (AdminCMCData) cmcControlObject.getValue();
    final AdminCMCData adminResponse = this.getAdminResponse(adminRequest);
    final CMCResponseModel responseModel = new CMCAdminResponseModel(
        cmcRequest.getNonce(),
        new CMCResponseStatus(CMCStatusType.success, Arrays.asList(cmcControlObject.getBodyPartID())),
        cmcRequest.getCmcRequestType(),
        adminResponse);

    return this.cmcResponseFactory.getCMCResponse(responseModel);
  }

  /**
   * Process the admin request data and return the resulting admin response data as part of service a custom CMC request
   *
   * @param adminRequest admin CMC request data
   * @return admin CMC response data
   * @throws CMCException on errors processing this request
   */
  protected abstract AdminCMCData getAdminResponse(AdminCMCData adminRequest) throws CMCException;

  /**
   * Process a request to get a certificate from the CA repository
   *
   * @param cmcRequest CMC request
   * @return CMC response
   * @throws CMCCaApiException error processing this request
   */
  protected CMCResponse processGetCertRequest(final CMCRequest cmcRequest) throws CMCCaApiException {
    List<BodyPartID> requestBodyParts = new ArrayList<>();
    try {
      final PKIData pkiData = cmcRequest.getPkiData();
      final CMCControlObject cmcControlObject =
          CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_getCert, pkiData);
      requestBodyParts = Arrays.asList(cmcControlObject.getBodyPartID());
      final GetCert getCert = (GetCert) cmcControlObject.getValue();
      final X500Name issuerName = (X500Name) getCert.getIssuerName().getName();
      if (this.caService.getCaCertificate().getSubject().equals(issuerName)) {
        final CertificateRecord certificateRecord =
            this.caService.getCaRepository().getCertificate(getCert.getSerialNumber());
        final X509CertificateHolder targetCertificateHolder =
            new X509CertificateHolder(certificateRecord.getCertificate());
        final CMCResponseModel responseModel = new CMCBasicCMCResponseModel(
            cmcRequest.getNonce(),
            new CMCResponseStatus(CMCStatusType.success, requestBodyParts),
            cmcRequest.getCmcRequestType(), null,
            Arrays.asList(CAUtils.getCert(targetCertificateHolder)));
        return this.cmcResponseFactory.getCMCResponse(responseModel);
      }
    }
    catch (final Exception ex) {
      throw new CMCCaApiException("Failure to process Get Cert reqeust", ex, requestBodyParts, CMCFailType.badRequest);
    }
    throw new CMCCaApiException("Get certificate request does not match CA issuer name", requestBodyParts,
        CMCFailType.badRequest);
  }

}
