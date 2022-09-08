/*
 * Copyright 2021-2022 Agency for Digital Government (DIGG)
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

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.GetCert;
import org.bouncycastle.asn1.cmc.OtherMsg;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.RevokeRequest;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import org.bouncycastle.asn1.cmc.TaggedContentInfo;
import org.bouncycastle.asn1.cmc.TaggedRequest;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestModel;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.cmc.model.request.impl.CMCAdminRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCCertificateRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCGetCertRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCRevokeRequestModel;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

/**
 * This class provides the logic for creating CMC requests. This class is intended to be instantiated as a bean.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCRequestFactory {

  /** Random source */
  private final static SecureRandom RNG = new SecureRandom();

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
  public CMCRequestFactory(final List<X509Certificate> signerCertChain, final ContentSigner signer) {
    this.signerCertChain = signerCertChain;
    this.signer = signer;
  }

  /**
   * Create a CMC Request
   *
   * @param cmcRequestModel model holding the data necessary to create a CMC request
   * @return CMC Request
   * @throws CMCMessageException on failure to create a valid CMC request
   */
  public CMCRequest getCMCRequest(final CMCRequestModel cmcRequestModel) throws CMCMessageException {
    final CMCRequest.CMCRequestBuilder requestBuilder = CMCRequest.builder();
    final CMCRequestType cmcRequestType = cmcRequestModel.getCmcRequestType();
    final Date messageTime = new Date();
    requestBuilder
        .cmcRequestType(cmcRequestType)
        .nonce(cmcRequestModel.getNonce());
    PKIData pkiData = null;
    try {
      switch (cmcRequestType) {
      case issueCert:
        pkiData = this.createCertRequest((CMCCertificateRequestModel) cmcRequestModel, messageTime);
        this.addCertRequestData(pkiData, requestBuilder);
        break;
      case revoke:
        pkiData = new PKIData(this.getCertRevocationControlSequence((CMCRevokeRequestModel) cmcRequestModel),
            new TaggedRequest[] {}, new TaggedContentInfo[] {}, new OtherMsg[] {});
        break;
      case admin:
        pkiData = this.createAdminRequest((CMCAdminRequestModel) cmcRequestModel);
        break;
      case getCert:
        pkiData = this.createGetCertRequest((CMCGetCertRequestModel) cmcRequestModel, messageTime);
        break;
      }
      requestBuilder
          .pkiData(pkiData)
          .cmcRequestBytes(CMCUtils.signEncapsulatedCMSContent(
              CMCObjectIdentifiers.id_cct_PKIData,
              pkiData, this.signerCertChain, this.signer));
    }
    catch (final Exception e) {
      throw new CMCMessageException("Error generating CMC request", e);
    }
    return requestBuilder.build();
  }

  private PKIData createGetCertRequest(final CMCGetCertRequestModel cmcRequestModel, final Date messageTime) {
    return new PKIData(this.getGetCertsControlSequence(cmcRequestModel, messageTime), new TaggedRequest[] {},
        new TaggedContentInfo[] {}, new OtherMsg[] {});
  }

  private TaggedAttribute[] getGetCertsControlSequence(
      final CMCGetCertRequestModel cmcRequestModel, final Date messageTime) {
    final List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel.getNonce());
    this.addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    final GeneralName gn = new GeneralName(cmcRequestModel.getIssuerName());
    final GetCert getCert = new GetCert(gn, cmcRequestModel.getSerialNumber());
    taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_getCert, getCert));
    return taggedAttributeList.toArray(new TaggedAttribute[0]);
  }

  private PKIData createAdminRequest(final CMCAdminRequestModel cmcRequestModel) {
    return new PKIData(this.getAdminControlSequence(cmcRequestModel), new TaggedRequest[] {},
        new TaggedContentInfo[] {},
        new OtherMsg[] {});
  }

  private TaggedAttribute[] getAdminControlSequence(final CMCAdminRequestModel cmcRequestModel) {
    final List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel.getNonce());
    this.addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    return taggedAttributeList.toArray(new TaggedAttribute[0]);
  }

  private PKIData createCertRequest(final CMCCertificateRequestModel cmcRequestModel, final Date messageTime)
      throws NoSuchAlgorithmException, OperatorCreationException, CRMFException, CMCMessageException {

    TaggedRequest taggedCertificateRequest;
    final BodyPartID certReqBodyPartId = getBodyPartId();
    final TaggedAttribute[] controlSequence =
        this.getCertRequestControlSequence(cmcRequestModel, cmcRequestModel.getNonce(),
            certReqBodyPartId);
    final PrivateKey certReqPrivate = cmcRequestModel.getCertReqPrivate();
    if (certReqPrivate != null) {
      final ContentSigner p10Signer = new JcaContentSignerBuilder(
          CAAlgorithmRegistry.getSigAlgoName(cmcRequestModel.getP10Algorithm()))
              .build(certReqPrivate);
      final CertificationRequest certificationRequest = CMCUtils.getCertificationRequest(
          cmcRequestModel.getCertificateModel(), p10Signer,
          new AttributeValueEncoder());
      taggedCertificateRequest = new TaggedRequest(
          new TaggedCertificationRequest(certReqBodyPartId, certificationRequest));
    }
    else {
      final CertificateRequestMessageBuilder crmfBuilder = CMCUtils.getCRMFRequestMessageBuilder(certReqBodyPartId,
          cmcRequestModel.getCertificateModel(), new AttributeValueEncoder());
      this.extendCertTemplate(crmfBuilder, cmcRequestModel);
      final CertificateRequestMessage certificateRequestMessage = crmfBuilder.build();
      taggedCertificateRequest = new TaggedRequest(certificateRequestMessage.toASN1Structure());
    }

    return new PKIData(controlSequence, new TaggedRequest[] { taggedCertificateRequest }, new TaggedContentInfo[] {},
        new OtherMsg[] {});
  }

  /**
   * Extension point for manipulating and extending the CRMF certificate template
   *
   * @param crmfBuilder the CRMF builder holding default certificate template data
   * @param cmcRequestModel CMC request model holding data about the CMC request to be built
   */
  protected void extendCertTemplate(final CertificateRequestMessageBuilder crmfBuilder,
      final CMCCertificateRequestModel cmcRequestModel) {
    // Override this function to extend crmf cert template based on cmcRequestModel
  }

  private static BodyPartID getBodyPartId() {
    return getBodyPartId(new BigInteger(31, RNG).add(BigInteger.ONE));
  }

  private static BodyPartID getBodyPartId(final BigInteger bodyPartId) {
    final long id = Long.parseLong(bodyPartId.toString(10));
    return new BodyPartID(id);
  }

  private TaggedAttribute[] getCertRevocationControlSequence(final CMCRevokeRequestModel cmcRequestModel) {
    final List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, cmcRequestModel.getNonce());
    this.addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    final RevokeRequest revokeRequest = new RevokeRequest(
        cmcRequestModel.getIssuerName(),
        new ASN1Integer(cmcRequestModel.getSerialNumber()),
        CRLReason.lookup(cmcRequestModel.getReason()),
        new ASN1GeneralizedTime(cmcRequestModel.getRevocationDate()), null, null);
    taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_revokeRequest, revokeRequest));
    return taggedAttributeList.toArray(new TaggedAttribute[0]);
  }

  private TaggedAttribute[] getCertRequestControlSequence(final CMCCertificateRequestModel cmcRequestModel,
      final byte[] nonce, final BodyPartID certReqBodyPartId) {
    final List<TaggedAttribute> taggedAttributeList = new ArrayList<>();
    addNonceControl(taggedAttributeList, nonce);
    this.addRegistrationInfoControl(taggedAttributeList, cmcRequestModel);
    if (cmcRequestModel.isLraPopWitness()) {
      final ASN1EncodableVector lraPopWitSeq = new ASN1EncodableVector();
      lraPopWitSeq.add(getBodyPartId());
      lraPopWitSeq.add(new DERSequence(certReqBodyPartId));
      taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_lraPOPWitness, new DERSequence(lraPopWitSeq)));
    }
    return taggedAttributeList.toArray(new TaggedAttribute[0]);
  }

  private void addRegistrationInfoControl(
      final List<TaggedAttribute> taggedAttributeList, final CMCRequestModel cmcRequestModel) {
    final byte[] registrationInfo = cmcRequestModel.getRegistrationInfo();
    if (registrationInfo != null) {
      taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_regInfo, new DEROctetString(registrationInfo)));
    }
  }

  /**
   * Add nonce data to a list of tagged attributes. This function can be used to include nonce in both CMC requests and
   * CMC responses
   *
   * @param taggedAttributeList list of tagged attributes to which the nonce should be added
   * @param nonce nonce data to be added
   */
  public static void addNonceControl(final List<TaggedAttribute> taggedAttributeList, final byte[] nonce) {
    if (nonce != null) {
      taggedAttributeList.add(getControl(CMCObjectIdentifiers.id_cmc_senderNonce, new DEROctetString(nonce)));
    }
  }

  /**
   * Get a CMC Control in the form of a {@link TaggedAttribute} based on the components OID, and a set of attribute
   * values. BodyPartID will be randomly generated.
   *
   * @param oid Control OID
   * @param values attribute values
   * @return {@link TaggedAttribute} containing CMC Control data
   */
  public static TaggedAttribute getControl(final ASN1ObjectIdentifier oid, final ASN1Encodable... values) {
    return getControl(oid, null, values);
  }

  /**
   * Get a CMC Control in the form of a {@link TaggedAttribute} based on the components OID, BodyPartID and a set of
   * attribute values
   *
   * @param oid Control OID
   * @param id BodyPartID or null to get a randomly generated BodyPartID
   * @param values attribute values
   * @return {@link TaggedAttribute} containing CMC Control data
   */
  public static TaggedAttribute getControl(
      final ASN1ObjectIdentifier oid, BodyPartID id, final ASN1Encodable... values) {
    if (id == null) {
      id = getBodyPartId();
    }
    final ASN1Set valueSet = getSet(values);
    return new TaggedAttribute(id, oid, valueSet);
  }

  /**
   * Construct an ASN.1 set of attribute values
   *
   * @param content attribute values
   * @return ASN.1 set of attribute values
   */
  public static ASN1Set getSet(final ASN1Encodable... content) {
    final ASN1EncodableVector valueSet = new ASN1EncodableVector();
    for (final ASN1Encodable data : content) {
      valueSet.add(data);
    }
    return new DERSet(valueSet);
  }

  /**
   * Adds a certificate request from PKIData to a CMC request builder. This allows the request builder to build a CMC
   * request that includes a certificate issuance request.
   *
   * @param pkiData PKIData holding the certificate request in the form of a PKCS#10 request or a CRMF request
   * @param cmcRequestBuilder CMC request builder to which the certificate request should be added
   */
  private void addCertRequestData(final PKIData pkiData, final CMCRequest.CMCRequestBuilder cmcRequestBuilder) {
    if (pkiData == null || pkiData.getReqSequence() == null) {
      return;
    }
    final TaggedRequest[] reqSequence = pkiData.getReqSequence();
    for (final TaggedRequest taggedRequest : reqSequence) {
      final ASN1Encodable taggedRequestValue = taggedRequest.getValue();
      if (taggedRequestValue instanceof TaggedCertificationRequest) {
        // This is a PKCS#10 request
        final TaggedCertificationRequest taggedCertReq = (TaggedCertificationRequest) taggedRequestValue;
        final ASN1Sequence taggedCertReqSeq = ASN1Sequence.getInstance(taggedCertReq.toASN1Primitive());
        final BodyPartID certReqBodyPartId = BodyPartID.getInstance(taggedCertReqSeq.getObjectAt(0));
        final CertificationRequest certificationRequest =
            CertificationRequest.getInstance(taggedCertReqSeq.getObjectAt(1));
        cmcRequestBuilder
            .certificationRequest(certificationRequest)
            .certReqBodyPartId(certReqBodyPartId);
        return;
      }
      if (taggedRequestValue instanceof CertReqMsg) {
        // This is a CRMF request
        final CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage(
            (CertReqMsg) taggedRequestValue);
        final ASN1Integer certReqId = ((CertReqMsg) taggedRequestValue).getCertReq().getCertReqId();
        final BodyPartID certReqBodyPartId = new BodyPartID(certReqId.longValueExact());
        cmcRequestBuilder
            .certificateRequestMessage(certificateRequestMessage)
            .certReqBodyPartId(certReqBodyPartId);
        return;
      }
    }
  }

}
