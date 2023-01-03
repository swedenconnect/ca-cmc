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
package se.swedenconnect.ca.cmc.auth;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CMCStatus;
import org.bouncycastle.asn1.cmc.CMCStatusInfoV2;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.GetCert;
import org.bouncycastle.asn1.cmc.LraPopWitness;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.RevokeRequest;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCControlObjectID;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.CertificateData;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.utils.CAUtils;

/**
 * Utility functions for parsing and creating CMC messages.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCUtils {

  /** Random source */
  public static final SecureRandom RNG = new SecureRandom();

  /** JSON object mapper */
  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  /**
   * Create a CRMF request message builder for a CRMF certificate request.
   *
   * @param requestId the ID of the created request
   * @param certificateModel model holding data about the certificate to be issued
   * @param attributeValueEncoder encoder for attribute values
   * @return CRMF request message builder
   * @throws CMCMessageException on error creating the builder
   */
  public static CertificateRequestMessageBuilder getCRMFRequestMessageBuilder(final BodyPartID requestId,
      final CertificateModel certificateModel, final AttributeValueEncoder attributeValueEncoder)
      throws CMCMessageException {

    try {
      final CertificateRequestMessageBuilder crmfBuilder =
          new CertificateRequestMessageBuilder(new BigInteger(String.valueOf(requestId.getID())));

      crmfBuilder.setSubject(CAUtils.getX500Name(certificateModel.getSubject(), attributeValueEncoder));

      final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
          ASN1Sequence.getInstance(certificateModel.getPublicKey().getEncoded()));
      crmfBuilder.setPublicKey(subjectPublicKeyInfo);

      final List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
      for (final ExtensionModel extensionModel : extensionModels) {
        final List<Extension> extensions = extensionModel.getExtensions();
        for (final Extension extension : extensions) {
          crmfBuilder.addExtension(extension.getExtnId(), extension.isCritical(), extension.getParsedValue());
        }
      }
      return crmfBuilder;
    }
    catch (final IOException e) {
      throw new CMCMessageException("Failed to create CRMF request builder - " + e.getMessage(), e);
    }

  }

  /**
   * Creates a PKCS10 request
   *
   * @param certificateModel data about the certificate to be requested
   * @param signer the signer of the PKCS10 request
   * @param attributeValueEncoder attribute value encoder
   * @return PKCS10 request
   * @throws CMCMessageException on errors creating the request
   */
  public static CertificationRequest getCertificationRequest(final CertificateModel certificateModel,
      final ContentSigner signer, final AttributeValueEncoder attributeValueEncoder) throws CMCMessageException {

    try {
      final X500Name subjectX500Name = CAUtils.getX500Name(certificateModel.getSubject(), attributeValueEncoder);
      final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
          ASN1Sequence.getInstance(certificateModel.getPublicKey().getEncoded()));

      final PKCS10CertificationRequestBuilder p10ReqBuilder =
          new PKCS10CertificationRequestBuilder(subjectX500Name, subjectPublicKeyInfo);
      final ExtensionsGenerator extGen = new ExtensionsGenerator();
      final List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
      for (final ExtensionModel extensionModel : extensionModels) {
        final List<Extension> extensions = extensionModel.getExtensions();
        for (final Extension extension : extensions) {
          extGen.addExtension(extension);
        }
      }
      p10ReqBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
      final PKCS10CertificationRequest pkcs10 = p10ReqBuilder.build(signer);
      return CertificationRequest.getInstance(pkcs10.toASN1Structure().toASN1Primitive());
    }
    catch (final IOException e) {
      throw new CMCMessageException("Failed to create PKCS#10 request - " + e.getMessage(), e);
    }
  }

  /**
   * Sign encapsulated CMS content
   *
   * @param contentType type of content OID
   * @param content content
   * @param signerCertChain certificate chain of the signer with the signer certificate first in the list and trust
   *          anchor last
   * @param signer {@link ContentSigner} for signing the data
   * @return the byte of the signed CMS signature with encapsulated signed data
   * @throws CMCMessageException on error executing the request
   */
  public static byte[] signEncapsulatedCMSContent(final ASN1ObjectIdentifier contentType, final ASN1Encodable content,
      final List<X509Certificate> signerCertChain, final ContentSigner signer) throws CMCMessageException {
    try {
      final Store<?> certs = new JcaCertStore(signerCertChain);
      final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      final org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(
          ASN1Primitive.fromByteArray(signerCertChain.get(0).getEncoded()));
      // final ContentSigner signer = new
      // JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(algorithm)).build(signKey);
      final JcaSignerInfoGeneratorBuilder builder =
          new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
      gen.addSignerInfoGenerator(builder.build(signer, new X509CertificateHolder(cert)));
      gen.addCertificates(certs);
      // final CMSTypedData encapsulatedContent = new PKCS7ProcessableObject(contentType, content);
      final CMSProcessableByteArray encapsulatedContent =
          new CMSProcessableByteArray(contentType, content.toASN1Primitive().getEncoded(ASN1Encoding.DER));
      final CMSSignedData resultSignedData = gen.generate(encapsulatedContent, true);
      return resultSignedData.toASN1Structure().getEncoded(ASN1Encoding.DL);
    }
    catch (GeneralSecurityException | CMSException | OperatorCreationException | IOException e) {
      final String msg = String.format("Failed to sign content - %s", e.getMessage());
      log.error("{}", msg, e);
      throw new CMCMessageException(msg, e);
    }
  }

  /**
   * Obtain a CMC Control object from a PKI response object
   *
   * @param asn1controlOid the OID of the target CMC Control
   * @param pkiResponse PKI response object holding CMC Control objects
   * @return {@link CMCControlObject}
   * @throws CMCMessageException error parsing the PKI response
   */
  public static CMCControlObject getCMCControlObject(final ASN1ObjectIdentifier asn1controlOid,
      final PKIResponse pkiResponse) throws CMCMessageException {
    return getCMCControlObject(asn1controlOid, getResponseControlSequence(pkiResponse));

  }

  /**
   * Obtain a CMC Control object from a PKI data object (request)
   *
   * @param asn1controlOid the OID of the target CMC Control
   * @param pkiData PKI data object holding CMC Control objects
   * @return {@link CMCControlObject}
   * @throws CMCMessageException error parsing the PKI data
   */
  public static CMCControlObject getCMCControlObject(final ASN1ObjectIdentifier asn1controlOid, final PKIData pkiData)
      throws CMCMessageException {
    final TaggedAttribute[] controlSequence = pkiData.getControlSequence();
    return getCMCControlObject(asn1controlOid, controlSequence);
  }

  /**
   * Obtain a CMC Control object from a list of {@link TaggedAttribute}
   *
   * @param asn1controlOid the OID of the target CMC Control
   * @param controlSequence a list of {@link TaggedAttribute}
   * @return {@link CMCControlObject}
   * @throws CMCMessageException error parsing the list of {@link TaggedAttribute}
   */
  private static CMCControlObject getCMCControlObject(final ASN1ObjectIdentifier asn1controlOid,
      final TaggedAttribute[] controlSequence) throws CMCMessageException {
    final CMCControlObjectID controlOid = CMCControlObjectID.getControlObjectID(asn1controlOid);
    final CMCControlObject.CMCControlObjectBuilder resultBuilder = CMCControlObject.builder().type(controlOid);
    for (final TaggedAttribute controlAttr : controlSequence) {
      final ASN1ObjectIdentifier attrType = controlAttr.getAttrType();
      if (attrType != null && attrType.equals(controlOid.getOid())) {
        resultBuilder
            .bodyPartID(controlAttr.getBodyPartID())
            .value(getRequestControlValue(controlOid, controlAttr.getAttrValues()));
      }
    }
    return resultBuilder.build();
  }

  /**
   * Get the value of a CMC Control. The value object type is determined from the control OID
   *
   * @param controlOid the OID of the CMC control
   * @param controlAttrVals a set of control attribute values
   * @return attribute value object
   * @throws CMCMessageException error parsing provided data
   */
  private static Object getRequestControlValue(final CMCControlObjectID controlOid, final ASN1Set controlAttrVals)
      throws CMCMessageException {
    // Get the basic data object
    final Object controlValue = getControlValue(controlOid, controlAttrVals);
    // If this is custom data, then attempt to extract the AdminCMCData object from the byte array
    if (CMCControlObjectID.regInfo.equals(controlOid) || CMCControlObjectID.responseInfo.equals(controlOid)) {
      final byte[] dataBytes = (byte[]) controlValue;
      return getBytesOrJsonObject(dataBytes, AdminCMCData.class);
    }
    return controlValue;
  }

  /**
   * Attempt to extract a particular object of a specified class from a JSON string, or else just return the actual
   * bytes.
   *
   * @param inputDataBytes the input data bytes
   * @param dataClass the object class to be extracted
   * @return object of the expected data class, or just the input bytes
   */
  private static Object getBytesOrJsonObject(final byte[] inputDataBytes, final Class<?> dataClass) {
    try {
      return OBJECT_MAPPER.readValue(inputDataBytes, dataClass);
    }
    catch (final Exception e) {
      return inputDataBytes;
    }
  }

  private static Object getControlValue(final CMCControlObjectID controlOid, final ASN1Set controlAttrVals)
      throws CMCMessageException {
    try {
      if (controlAttrVals.size() == 0) {
        log.debug("No values - Returning null");
        return null;
      }
      final ASN1Encodable firstObject = controlAttrVals.getObjectAt(0);
      if (firstObject == null) {
        log.debug("No control value - Returning null");
        return null;
      }

      if (CMCControlObjectID.regInfo.equals(controlOid)
          || CMCControlObjectID.responseInfo.equals(controlOid)
          || CMCControlObjectID.senderNonce.equals(controlOid)
          || CMCControlObjectID.recipientNonce.equals(controlOid)) {
        return ASN1OctetString.getInstance(firstObject).getOctets();
      }
      if (CMCControlObjectID.getCert.equals(controlOid)) {
        return GetCert.getInstance(firstObject);
      }
      if (CMCControlObjectID.lraPOPWitness.equals(controlOid)) {
        return LraPopWitness.getInstance(firstObject);
      }
      if (CMCControlObjectID.revokeRequest.equals(controlOid)) {
        return RevokeRequest.getInstance(firstObject);
      }
      if (CMCControlObjectID.statusInfoV2.equals(controlOid)) {
        return CMCStatusInfoV2.getInstance(firstObject);
      }
    }
    catch (final Exception e) {
      throw new CMCMessageException("Error extracting CMC control value", e);
    }
    log.debug("Unsupported CMC control message {} - returning null", controlOid);
    return null;
  }

  /**
   * Return the status code value of CMCStatus
   *
   * @param cmcStatus CMCStatus
   * @return integer value
   */
  public static int getCMCStatusCode(final CMCStatus cmcStatus) {
    final ASN1Integer cmcStatusAsn1Int = (ASN1Integer) cmcStatus.toASN1Primitive();
    return cmcStatusAsn1Int.intPositiveValueExact();
  }

  /**
   * Get the control sequence array from a CMC PKI Response
   *
   * @param pkiResponse CMC PKI Response
   * @return control data sequence in the form of an array of {@link TaggedAttribute}
   */
  public static TaggedAttribute[] getResponseControlSequence(final PKIResponse pkiResponse) {
    final List<TaggedAttribute> attributeList = new ArrayList<>();
    final ASN1Sequence controlSequence = pkiResponse.getControlSequence();
    if (controlSequence.size() > 0) {
      final Iterator<ASN1Encodable> iterator = controlSequence.iterator();
      while (iterator.hasNext()) {
        final TaggedAttribute csAttr = TaggedAttribute.getInstance(iterator.next());
        attributeList.add(csAttr);
      }
    }
    return attributeList.toArray(new TaggedAttribute[0]);
  }

  /**
   * Return a list of certificate bytes representing a list of X509 Certificates
   *
   * @param certificateList list of certificates
   * @return list of certificate bytes
   * @throws CertificateException on certificate encoding errors
   */
  public static List<byte[]> getCertByteList(final List<X509Certificate> certificateList) throws CertificateException {
    final List<byte[]> certByteList = new ArrayList<>();
    for (final X509Certificate cert : certificateList) {
      certByteList.add(cert.getEncoded());
    }
    return certByteList;
  }

  /**
   * Return a list of certificate bytes representing a list of X509 Certificates
   *
   * @param certificateList list of certificates
   * @return list of certificate bytes
   * @throws CertificateException on certificate encoding errors
   */
  public static List<byte[]> getCerHolderByteList(final List<X509CertificateHolder> certificateList)
      throws CertificateException {
    try {
      final List<byte[]> certByteList = new ArrayList<>();
      for (final X509CertificateHolder cert : certificateList) {
        certByteList.add(cert.getEncoded());
      }
      return certByteList;
    }
    catch (final IOException e) {
      throw new CertificateException("Failed to get encoded certificate(s)", e);
    }
  }

  /**
   * Get CA information from a CMC response
   *
   * @param cmcResponse CMC response
   * @return {@link CAInformation}
   * @throws CMCMessageException error parsing data
   */
  public static CAInformation getCAInformation(final CMCResponse cmcResponse) throws CMCMessageException {
    try {
      final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
      return CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), CAInformation.class);
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to parse CA information", e);
    }
  }

  /**
   * Get AdminCMCData from a CMC response
   *
   * @param cmcResponse CMC response
   * @return {@link AdminCMCData}
   * @throws CMCMessageException error parsing data
   */
  public static AdminCMCData getAdminCMCData(final CMCResponse cmcResponse) throws CMCMessageException {
    final CMCControlObject responseControlObject =
        getResponseControlObject(cmcResponse, CMCObjectIdentifiers.id_cmc_responseInfo);
    return (AdminCMCData) responseControlObject.getValue();
  }

  /**
   * Get CMC control object from a CMC response
   *
   * @param cmcResponse CMC response
   * @param controlObjOid the OID fot he CMC response
   * @return a CMCControlObject
   * @throws CMCMessageException error parsing data
   */
  public static CMCControlObject getResponseControlObject(final CMCResponse cmcResponse,
      final ASN1ObjectIdentifier controlObjOid) throws CMCMessageException {
    final TaggedAttribute[] taggedAttributes = CMCUtils.getResponseControlSequence(cmcResponse.getPkiResponse());
    return CMCUtils.getCMCControlObject(controlObjOid, taggedAttributes);
  }

  /**
   * Get all serial numbers of a CA repository from a CMC response
   *
   * @param cmcResponse CMC response
   * @return list of certificate serial numbers
   * @throws CMCMessageException error parsing data
   */
  public static List<BigInteger> getAllSerials(final CMCResponse cmcResponse) throws CMCMessageException {
    try {
      final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
      final List<String> serials = CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), new TypeReference<>() {});
      return serials.stream().map(s -> new BigInteger(s, 16)).collect(Collectors.toList());
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to parse certificate serial numbers from CMC response", e);
    }
  }

  /**
   * Gets the list of certificates contained in a CMC response
   *
   * @param cmcResponse CMC response
   * @return list of certificates
   * @throws CMCMessageException error parsing data
   */
  public static List<CertificateData> getCertList(final CMCResponse cmcResponse) throws CMCMessageException {
    try {
    final AdminCMCData adminCMCData = getAdminCMCData(cmcResponse);
    return CMCUtils.OBJECT_MAPPER.readValue(adminCMCData.getData(), new TypeReference<>() {});
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to parse certificates from CMC response", e);
    }
  }

  /**
   * Get the value of the signed signingTime attribute from a CMS signed CMC message
   *
   * @param cmsContentInfo CMS content info bytes
   * @return signing time attribute value if present, or null
   * @throws CMCMessageException error parsing CMS data
   */
  public static Date getSigningTime(final byte[] cmsContentInfo) throws CMCMessageException {
    try {
      return getSigningTime(new CMSSignedData(cmsContentInfo));
    }
    catch (final CMSException e) {
      throw new CMCMessageException("Failed to parse signed signingTime attribute from a CMS signed CMC message", e);
    }
  }

  /**
   * Get the value of the signed signingTime attribute from a CMS signed CMC message
   *
   * @param signedData CMS signed data
   * @return signing time attribute value if present, or null
   */
  public static Date getSigningTime(final CMSSignedData signedData) {
    final SignerInformation signerInformation = signedData.getSignerInfos().iterator().next();
    final Attribute signingTimeAttr = signerInformation.getSignedAttributes().get(CMSAttributes.signingTime);
    return signingTimeAttr == null
        ? null
        : Time.getInstance(signingTimeAttr.getAttrValues().getObjectAt(0)).getDate();
  }

}
