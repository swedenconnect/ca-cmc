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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CMCStatusInfoV2Builder;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.operator.ContentSigner;

import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.response.CMCResponseModel;

/**
 * This class is intended to be used as a bean for creating CMC responses.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCResponseFactory {

  /** Signer certificate chain for signing CMC requests */
  private final List<X509Certificate> signerCertChain;

  /** A CMS Content signer used to sign CMC requests */
  private final ContentSigner signer;

  /**
   * Constructor
   *
   * @param signerCertChain signer certificate chain for signing CMC requests
   * @param signer a CMS Content signer used to sign CMC requests
   */
  public CMCResponseFactory(final List<X509Certificate> signerCertChain, final ContentSigner signer) {
    this.signerCertChain = signerCertChain;
    this.signer = signer;
  }

  /**
   * Create a CMC response
   *
   * @param cmcResponseModel response model holding data necessary to create the CMC response
   * @return {@link CMCResponse}
   * @throws CMCMessageException on errors creating a CMC response
   */
  public CMCResponse getCMCResponse(final CMCResponseModel cmcResponseModel) throws CMCMessageException {
    final PKIResponse pkiResponseData = this.getPKIResponseData(cmcResponseModel);
    final List<X509Certificate> cmsCertList = new ArrayList<>(this.signerCertChain);
    List<X509Certificate> outputCerts = cmcResponseModel.getReturnCertificates();
    if (outputCerts != null) {
      cmsCertList.addAll(outputCerts);
    }
    else {
      outputCerts = new ArrayList<>();
    }

    final CMCResponse.CMCResponseBuilder responseBuilder = CMCResponse.builder()
        .nonce(cmcResponseModel.getNonce())
        .pkiResponse(pkiResponseData)
        .cmcResponseBytes(CMCUtils.signEncapsulatedCMSContent(CMCObjectIdentifiers.id_cct_PKIResponse,
            pkiResponseData, cmsCertList, this.signer))
        .returnCertificates(outputCerts)
        .responseStatus(cmcResponseModel.getCmcResponseStatus())
        .cmcRequestType(cmcResponseModel.getCmcRequestType());

    return responseBuilder.build();
  }

  private PKIResponse getPKIResponseData(final CMCResponseModel cmcResponseModel) {

    final ASN1EncodableVector pkiResponseSeq = new ASN1EncodableVector();
    final ASN1EncodableVector controlSeq = new ASN1EncodableVector();
    final ASN1EncodableVector cmsSeq = new ASN1EncodableVector();
    final ASN1EncodableVector otherMsgSeq = new ASN1EncodableVector();

    final List<TaggedAttribute> controlAttrList = this.getControlAttributes(cmcResponseModel);
    for (final TaggedAttribute contrAttr : controlAttrList) {
      controlSeq.add(contrAttr.toASN1Primitive());
    }
    pkiResponseSeq.add(new DERSequence(controlSeq));
    pkiResponseSeq.add(new DERSequence(cmsSeq));
    pkiResponseSeq.add(new DERSequence(otherMsgSeq));

    return PKIResponse.getInstance(new DERSequence(pkiResponseSeq));
  }

  private List<TaggedAttribute> getControlAttributes(final CMCResponseModel cmcResponseModel) {

    final List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcResponseModel.getNonce());
    // Add response status and fail info
    this.addStatusControl(taggedAttributeList, cmcResponseModel);

    // Add response info data
    final byte[] responseInfo = cmcResponseModel.getResponseInfo();
    if (responseInfo != null) {
      taggedAttributeList.add(
          CMCRequestFactory.getControl(CMCObjectIdentifiers.id_cmc_responseInfo, new DEROctetString(responseInfo)));
    }
    return taggedAttributeList;
  }

  /**
   * Adds nonce data to a list of tagged attributes
   *
   * @param taggedAttributeList list of tagged attributes
   * @param nonce nonce data
   */
  public static void addNonceControl(final List<TaggedAttribute> taggedAttributeList, final byte[] nonce) {
    if (nonce != null) {
      taggedAttributeList
          .add(CMCRequestFactory.getControl(CMCObjectIdentifiers.id_cmc_recipientNonce, new DEROctetString(nonce)));
    }
  }

  private void addStatusControl(final List<TaggedAttribute> taggedAttributeList,
      final CMCResponseModel cmcResponseModel) {
    final CMCResponseStatus cmcResponseStatus = cmcResponseModel.getCmcResponseStatus();
    final CMCStatusType cmcStatusType = cmcResponseStatus.getStatus();
    final CMCFailType cmcFailType = cmcResponseStatus.getFailType();
    final String message = cmcResponseStatus.getMessage();
    final CMCStatusInfoV2Builder statusBuilder = new CMCStatusInfoV2Builder(cmcStatusType.getCmcStatus(),
        cmcResponseStatus.getBodyPartIDList().toArray(new BodyPartID[0]));
    if (!cmcStatusType.equals(CMCStatusType.success) && cmcFailType != null) {
      statusBuilder.setOtherInfo(cmcFailType.getCmcFailInfo());
    }
    if (message != null) {
      statusBuilder.setStatusString(message);
    }
    taggedAttributeList
        .add(CMCRequestFactory.getControl(CMCObjectIdentifiers.id_cmc_statusInfoV2, statusBuilder.build()));
  }

}
