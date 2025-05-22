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
package se.swedenconnect.ca.cmc.auth.impl;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.auth.CMCAuthorizationException;
import se.swedenconnect.ca.cmc.auth.CMCValidationException;
import se.swedenconnect.ca.cmc.auth.CMCValidationResult;
import se.swedenconnect.ca.cmc.auth.CMCValidator;

/**
 * Abstract implementation of the CMC Validator interface
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractCMCValidator implements CMCValidator {

  /** {@inheritDoc} */
  @Override
  public CMCValidationResult validateCMC(final byte[] cmcMessage) {

    final CMCValidationResult result = new CMCValidationResult();
    if (this.isSimpleCMCResponse(result, cmcMessage)) {
      return result;
    }

    try {
      final CMSSignedData cmsSignedData = new CMSSignedData(cmcMessage);
      final ASN1ObjectIdentifier contentType = cmsSignedData.getSignedContent().getContentType();
      if (contentType.equals(CMCObjectIdentifiers.id_cct_PKIData)
          || contentType.equals(CMCObjectIdentifiers.id_cct_PKIResponse)) {
        result.setContentType(contentType);
      }
      else {
        result.setValid(false);
        result.setErrorMessage("Illegal CMC data content type");
        result.setException(new CMCMessageException("Illegal CMC data content type"));
        return result;
      }
      result.setSignedData(cmsSignedData);

      final List<X509CertificateHolder> trustedSignerCertChain = this.verifyCMSSignature(cmsSignedData);
      this.verifyAuthorization(trustedSignerCertChain.get(0), contentType, cmsSignedData);
      // Set result conclusion
      result.setSignerCertificatePath(trustedSignerCertChain);
      result.setSimpleResponse(false);
      result.setValid(true);
    }
    catch (final CMCAuthorizationException e) {
      result.setValid(false);
      result.setException(e);
      result.setErrorMessage(e.getMessage());
    }
    catch (final CMCValidationException e) {
      result.setValid(false);
      result.setException(e);
      result.setErrorMessage("CMC signature validation failed: " + e.getMessage());
    }
    catch (final Exception e) {
      result.setValid(false);
      result.setException(e);
      result.setErrorMessage("Error parsing CMC message: " + e.toString());
    }

    return result;
  }

  /**
   * Verifies the CMS signature.
   *
   * @param cmsSignedData the signed data to verify
   * @return The signing certificate chain if the verification was successful
   * @throws CMCValidationException if signature validation failed
   */
  protected abstract List<X509CertificateHolder> verifyCMSSignature(final CMSSignedData cmsSignedData)
      throws CMCValidationException;

  /**
   * Verifies the authorization of the signer to provide this CMC message or request the specified operations
   *
   * @param signer the verified signer of this CMC message
   * @param contentType the CMC encapsulated data content type
   * @param cmsSignedData the CMC message signed data to be authorized
   * @throws CMCAuthorizationException if authorization fails
   */
  protected abstract void verifyAuthorization(final X509CertificateHolder signer, final ASN1ObjectIdentifier contentType,
      final CMSSignedData cmsSignedData) throws CMCAuthorizationException;

  private boolean isSimpleCMCResponse(final CMCValidationResult result, final byte[] cmcMessage) {
    new ArrayList<>();

    try (final ASN1InputStream ain = new ASN1InputStream(cmcMessage)) {
      final ContentInfo cmsContentInfo = ContentInfo.getInstance(ain.readObject());
      if (!cmsContentInfo.getContentType().equals(CMSObjectIdentifiers.signedData)) {
        // The Body of the CMS ContentInfo MUST be SignedData
        return false;
      }
      final SignedData signedData = SignedData.getInstance(cmsContentInfo.getContent());
      final ASN1Set signerInfos = signedData.getSignerInfos();
      if (signerInfos != null && signerInfos.size() > 0) {
        // This is not a simple response if signerInfos is present
        return false;
      }
      // This is a simple response
      return true;
    }
    catch (final Exception e) {
      log.debug("Failed to parse response as valid CMS data");
      return false;
    }
  }
}
