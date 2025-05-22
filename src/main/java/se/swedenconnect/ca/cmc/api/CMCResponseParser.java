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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCFailInfo;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CMCStatusInfoV2;
import org.bouncycastle.asn1.cmc.OtherStatusInfo;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.engine.utils.CAUtils;

/**
 * Parser of CMC response data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCResponseParser {

  /**
   * A validator used to validate signatures on a CMC request as well as the authorization granted to the CMC signer to
   * make this request
   */
  private final CMCValidator validator;

  /**
   * The public key of the CA used to verify which of the return certificates that actually are issued by the responding
   * CA
   */
  private final PublicKey caPublicKey;

  /**
   * Constructor
   *
   * @param validator validator for validating signature on the response and the authorization of the responder
   * @param caPublicKey public key of the CA
   */
  public CMCResponseParser(final CMCValidator validator, final PublicKey caPublicKey) {
    this.validator = validator;
    this.caPublicKey = caPublicKey;
  }

  /**
   * Parsing a CMC response
   *
   * @param cmcResponseBytes the bytes of a CMC response
   * @param cmcRequestType the type of CMC request this response is related to
   * @return {@link CMCResponse}
   * @throws CMCMessageException on error parsing the CMC response bytes
   */
  public CMCResponse parseCMCresponse(final byte[] cmcResponseBytes, final CMCRequestType cmcRequestType)
      throws CMCMessageException {

    final CMCResponse.CMCResponseBuilder responseBuilder = CMCResponse.builder();
    responseBuilder
        .cmcResponseBytes(cmcResponseBytes)
        .cmcRequestType(cmcRequestType);

    boolean expectCertsOnSuccess;
    switch (cmcRequestType) {
    case issueCert:
    case getCert:
      expectCertsOnSuccess = true;
      break;
    default:
      expectCertsOnSuccess = false;
    }

    final CMCValidationResult cmcValidationResult = this.validator.validateCMC(cmcResponseBytes);
    if (!CMCObjectIdentifiers.id_cct_PKIResponse.equals(cmcValidationResult.getContentType())) {
      throw new CMCMessageException("Illegal CMS content type for CMC request");
    }
    if (!cmcValidationResult.isValid()) {
      throw new CMCMessageException(cmcValidationResult.getErrorMessage(), cmcValidationResult.getException());
    }

    try {
      final CMSSignedData signedData = cmcValidationResult.getSignedData();
      PKIResponse pkiResponse = null;
      try (final ASN1InputStream as = new ASN1InputStream((byte[]) signedData.getSignedContent().getContent())) {
        pkiResponse = PKIResponse.getInstance(as.readObject());
      }
      responseBuilder.pkiResponse(pkiResponse);
      final byte[] nonce =
          (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_recipientNonce, pkiResponse).getValue();
      final CMCStatusInfoV2 statusInfoV2 =
          (CMCStatusInfoV2) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_statusInfoV2,
              pkiResponse).getValue();
      final CMCResponseStatus responseStatus = this.getResponseStatus(statusInfoV2);
      responseBuilder
          .nonce(nonce)
          .responseStatus(responseStatus);
      if (responseStatus.getStatus().equals(CMCStatusType.success) && expectCertsOnSuccess) {
        // Success response where return certificates are expected. Get return certificates
        responseBuilder.returnCertificates(this.getResponseCertificates(signedData, cmcValidationResult));
      }
      else {
        // No response success or no certificates expected in response. Return empty return certificate list
        responseBuilder.returnCertificates(new ArrayList<>());
      }
    }
    catch (final Exception e) {
      log.debug("Error parsing PKIResponse Data from CMC response", e);
      throw new CMCMessageException("Error parsing PKIResponse Data from CMC response", e);
    }
    return responseBuilder.build();
  }

  CMCResponseStatus getResponseStatus(final CMCStatusInfoV2 statusInfoV2) {
    final CMCFailType cmcFailType = getCmcFailType(statusInfoV2);
    final CMCStatusType cmcStatus = CMCStatusType.getCMCStatusType(statusInfoV2.getcMCStatus());
    final String statusString = statusInfoV2.getStatusStringUTF8() != null
        ? statusInfoV2.getStatusStringUTF8().getString()
        : null;
    final BodyPartID[] bodyList = statusInfoV2.getBodyList();
    final CMCResponseStatus cmcResponseStatus = new CMCResponseStatus(
        cmcStatus, cmcFailType, statusString, Arrays.asList(bodyList));
    return cmcResponseStatus;
  }

  /**
   * Get CMC fail type from CMC status info V2
   *
   * @param statusInfoV2 status info V2 data
   * @return {@link CMCFailType}
   */
  public static CMCFailType getCmcFailType(final CMCStatusInfoV2 statusInfoV2) {
    final OtherStatusInfo otherStatusInfo = statusInfoV2.getOtherStatusInfo();
    if (otherStatusInfo != null && otherStatusInfo.isFailInfo()) {
      final CMCFailInfo cmcFailInfo = CMCFailInfo.getInstance(otherStatusInfo.toASN1Primitive());
      return CMCFailType.getCMCFailType(cmcFailInfo);
    }
    return null;
  }

  /**
   * The process here is a bit complicated since the return certificates are mixed with the CMC signing certificates
   * which may be issued by the CMC CA. The algorithm is as follows:
   * <p>
   * 1) List all certificates in the CMS signature 2) Remove all certs not issued by the CA 3) If more than one
   * certificate remains, remove any trusted CMS signer certificate
   *
   * @param signedData
   * @param cmcValidationResult
   * @return
   * @throws CertificateException
   * @throws IOException
   */
  private List<X509Certificate> getResponseCertificates(final CMSSignedData signedData,
      final CMCValidationResult cmcValidationResult) throws CertificateException, CMCMessageException {

    try {
      final Collection<X509CertificateHolder> certsInCMS = signedData.getCertificates().getMatches(null);
      final List<X509Certificate> certificateList = new ArrayList<>();
      for (final X509CertificateHolder certificateHolder : certsInCMS) {
        certificateList.add(CAUtils.getCert(certificateHolder));
      }
      // Remove all certs not issued by the CA
      final List<X509Certificate> caIssuedCertificateList = new ArrayList<>();
      for (final X509Certificate cmsCert : certificateList) {
        try {
          cmsCert.verify(this.caPublicKey);
          caIssuedCertificateList.add(cmsCert);
        }
        catch (InvalidKeyException | SignatureException e) {
          continue;
        }
        catch (final Exception e) {
          throw new CMCMessageException("Invalid return certificate in CMC response");
        }
      }

      if (caIssuedCertificateList.size() < 2) {
        return caIssuedCertificateList;
      }

      // More than 1 remaining cert. Remove any trusted CMS signer certificate
      final List<X509Certificate> filteredCertificateList = new ArrayList<>();
      final List<X509Certificate> cmsSignerCertificatePath =
          CAUtils.getCertList(cmcValidationResult.getSignerCertificatePath());
      for (final X509Certificate caIssuedCert : caIssuedCertificateList) {
        if (!cmsSignerCertificatePath.contains(caIssuedCert)) {
          filteredCertificateList.add(caIssuedCert);
        }
      }
      return filteredCertificateList;
    }
    catch (final IOException e) {
      throw new CMCMessageException("Invalid certificate(s)", e);
    }
  }
}
