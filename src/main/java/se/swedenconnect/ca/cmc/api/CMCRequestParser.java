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
package se.swedenconnect.ca.cmc.api;

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.LraPopWitness;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import org.bouncycastle.asn1.cmc.TaggedRequest;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cms.CMSSignedData;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.auth.CMCReplayChecker;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * Parser for CMC Request data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCRequestParser {

  /**
   * A validator used to validate signatures on a CMC request as well as the authorization granted to the CMC signer to
   * make this request
   */
  private final CMCValidator validator;
  /** Replay checker used to verify that the CMC message is not a replay of an old request */
  private final CMCReplayChecker replayChecker;

  /**
   * Constructor for the CMC data parser
   *
   * @param validator the validator used to validate the signature and authorization of the CMC signer to provide a CMC
   *          request
   * @param cmcReplayChecker replay checker detecting if a CMC request is a replay of an old CMC request
   */
  public CMCRequestParser(final CMCValidator validator, final CMCReplayChecker cmcReplayChecker) {
    this.validator = validator;
    this.replayChecker = cmcReplayChecker;
  }

  /**
   * Parse CMC request
   *
   * @param cmcRequestBytes the bytes of a CMC request
   * @return {@link CMCRequest}
   * @throws CMCMessageException on error parsing the CMC request bytes
   */
  public CMCRequest parseCMCrequest(final byte[] cmcRequestBytes) throws CMCMessageException {
    final CMCRequest cmcRequest = new CMCRequest();
    cmcRequest.setCmcRequestBytes(cmcRequestBytes);

    final CMCValidationResult cmcValidationResult = this.validator.validateCMC(cmcRequestBytes);
    if (!CMCObjectIdentifiers.id_cct_PKIData.equals(cmcValidationResult.getContentType())) {
      throw new CMCMessageException("Illegal CMS content type for CMC request");
    }
    if (!cmcValidationResult.isValid()) {
      // Validation failed attempt to get nonce for an error response;
      byte[] nonce = null;
      try {
        final CMSSignedData signedData = cmcValidationResult.getSignedData();
        try (final ASN1InputStream as = new ASN1InputStream((byte[]) signedData.getSignedContent().getContent())) {
          final PKIData pkiData = PKIData.getInstance(as.readObject());
          nonce = (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_senderNonce, pkiData).getValue();
        }
      }
      catch (final Exception e) {
        throw new CMCMessageException("Unable to retrieve nonce value", e);
      }
      throw new CMCParsingException(cmcValidationResult.getErrorMessage(), nonce);
    }
    try {
      final CMSSignedData signedData = cmcValidationResult.getSignedData();
      PKIData pkiData = null;
      try (final ASN1InputStream as = new ASN1InputStream((byte[]) signedData.getSignedContent().getContent())) {
        pkiData = PKIData.getInstance(as.readObject());
      }
      this.replayChecker.validate(signedData);
      cmcRequest.setPkiData(pkiData);
      // Get certification request
      final TaggedRequest[] reqSequence = pkiData.getReqSequence();
      if (reqSequence.length > 0) {
        final TaggedRequest taggedRequest = reqSequence[0];
        final ASN1Encodable taggedRequestValue = taggedRequest.getValue();
        boolean popCheckOK = false;
        if (taggedRequestValue instanceof TaggedCertificationRequest) {
          final TaggedCertificationRequest taggedCertReq = (TaggedCertificationRequest) taggedRequestValue;
          final ASN1Sequence taggedCertReqSeq = ASN1Sequence.getInstance(taggedCertReq.toASN1Primitive());
          final BodyPartID certReqBodyPartId = BodyPartID.getInstance(taggedCertReqSeq.getObjectAt(0));
          cmcRequest.setCertReqBodyPartId(certReqBodyPartId);
          final CertificationRequest certificationRequest =
              CertificationRequest.getInstance(taggedCertReqSeq.getObjectAt(1));
          cmcRequest.setCertificationRequest(certificationRequest);
          popCheckOK = true;
        }
        if (taggedRequestValue instanceof CertReqMsg) {
          final CertificateRequestMessage certificateRequestMessage =
              new CertificateRequestMessage((CertReqMsg) taggedRequestValue);
          cmcRequest.setCertificateRequestMessage(certificateRequestMessage);
          final ASN1Integer certReqId = ((CertReqMsg) taggedRequestValue).getCertReq().getCertReqId();
          final BodyPartID certReqBodyPartId = new BodyPartID(certReqId.longValueExact());
          cmcRequest.setCertReqBodyPartId(certReqBodyPartId);
          popCheckOK = this.isLraWitnessMatch(pkiData, certReqBodyPartId);
        }
        if (!popCheckOK) {
          throw new IllegalArgumentException("POP check failed");
        }
      }
      this.setRequestType(cmcRequest);
      final byte[] nonce =
          (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_senderNonce, pkiData).getValue();
      cmcRequest.setNonce(nonce);
    }
    catch (final Exception e) {
      if (e instanceof CMCMessageException) {
        throw (CMCMessageException) e;
      }
      log.debug("Error parsing PKI Data from CMC request: {}", e.toString());
      throw new CMCMessageException("Error parsing PKI Data from CMC request", e);
    }
    return cmcRequest;
  }

  private boolean isLraWitnessMatch(final PKIData pkiData, final BodyPartID certReqBodyPartId) throws CMCMessageException {
    final LraPopWitness lraPopWitness =
        (LraPopWitness) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_lraPOPWitness, pkiData)
            .getValue();
    if (lraPopWitness != null) {
      final BodyPartID[] bodyIds = lraPopWitness.getBodyIds();
      return Arrays.asList(bodyIds).contains(certReqBodyPartId);
    }
    return false;
  }

  private void setRequestType(final CMCRequest cmcRequest) throws CMCMessageException {
    if (cmcRequest.getCertificationRequest() != null || cmcRequest.getCertificateRequestMessage() != null) {
      cmcRequest.setCmcRequestType(CMCRequestType.issueCert);
      return;
    }
    if (CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest, cmcRequest.getPkiData())
        .getValue() != null) {
      cmcRequest.setCmcRequestType(CMCRequestType.revoke);
      return;
    }
    if (CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_getCert, cmcRequest.getPkiData()).getValue() != null) {
      cmcRequest.setCmcRequestType(CMCRequestType.getCert);
      return;
    }
    final Object regInfoObj =
        CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_regInfo, cmcRequest.getPkiData()).getValue();
    if (regInfoObj instanceof AdminCMCData) {
      cmcRequest.setCmcRequestType(CMCRequestType.admin);
      return;
    }
    throw new CMCMessageException("Illegal request type");
  }

}
