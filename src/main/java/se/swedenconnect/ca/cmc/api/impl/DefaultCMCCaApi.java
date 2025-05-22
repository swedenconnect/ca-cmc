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

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.LraPopWitness;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

import se.swedenconnect.ca.cmc.CMCException;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.GenericExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.EncodedCertNameModel;

/**
 * Default CMC API implementation. This API implementation extends the {@link AbstractAdminCMCCaApi} providing default
 * functionality for processing CMC requests. This implementation only provides the functionality for creating the
 * Certificate issuing model data used as input for Certificate Issuance.
 *
 * Modifications of this class may implement other rules, checks or overrides to what extensions or certificate data
 * that is accepted in issued certificates based on a CMC request.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCMCCaApi extends AbstractAdminCMCCaApi {

  /**
   * Constructor
   *
   * @param caService the CA service providing CA service operations
   * @param cmcRequestParser parser for parsing CMC requests
   * @param cmcResponseFactory factory for creating CMC responses
   */
  public DefaultCMCCaApi(final CAService caService,
      final CMCRequestParser cmcRequestParser, final CMCResponseFactory cmcResponseFactory) {
    super(caService, cmcRequestParser, cmcResponseFactory);
  }

  /** {@inheritDoc} */
  @Override
  CertificateModel getCertificateModel(final CMCRequest cmcRequest) throws CMCException {
    final CertificationRequest certificationRequest = cmcRequest.getCertificationRequest();
    final CertificateRequestMessage certificateRequestMessage = cmcRequest.getCertificateRequestMessage();

    if (certificationRequest != null) {
      return this.getCertificateModelFromPKCS10(certificationRequest);
    }

    final CMCControlObject lraPWObject =
        CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_lraPOPWitness, cmcRequest.getPkiData());
    final LraPopWitness lraPopWitness = (LraPopWitness) lraPWObject.getValue();

    return this.getCertificateModelFromCRMF(certificateRequestMessage, lraPopWitness,
        cmcRequest.getCertReqBodyPartId());
  }

  private CertificateModel getCertificateModelFromCRMF(final CertificateRequestMessage certificateRequestMessage,
      final LraPopWitness lraPopWitness, final BodyPartID certReqBodyPartId) throws CMCMessageException {

    // Check POP
    if (lraPopWitness == null) {
      throw new CMCMessageException("Certificate request message format requests must hav LRA POP Witness set");
    }
    final List<Long> lraPopIdList = Arrays.asList(lraPopWitness.getBodyIds()).stream()
        .map(BodyPartID::getID)
        .collect(Collectors.toList());
    if (!lraPopIdList.contains(certReqBodyPartId.getID())) {
      throw new CMCMessageException("No matching LRA POP Witness ID in CRMF request");
    }

    final CertTemplate certTemplate = certificateRequestMessage.getCertTemplate();
    final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    final PublicKey publicKey;
    try {
      publicKey = converter.getPublicKey(certTemplate.getPublicKey());
    }
    catch (final PEMException e) {
      throw new CMCMessageException("Failed to get public key from certificate template", e);
    }
    final Extensions extensions = certTemplate.getExtensions();
    final ASN1ObjectIdentifier[] extensionOIDs = extensions.getExtensionOIDs();
    final List<ExtensionModel> extensionModelList = new ArrayList<>();
    for (final ASN1ObjectIdentifier extOid : extensionOIDs) {
      final Extension extension = extensions.getExtension(extOid);
      extensionModelList.add(new GenericExtensionModel(
          extension.getExtnId(),
          extension.getParsedValue().toASN1Primitive(),
          extension.isCritical()));
    }

    final CertificateModel certificateModel = CertificateModel.builder()
        .publicKey(publicKey)
        .subject(new EncodedCertNameModel(certTemplate.getSubject()))
        .extensionModels(extensionModelList)
        .build();
    return certificateModel;
  }

  private CertificateModel getCertificateModelFromPKCS10(final CertificationRequest certificationRequest)
      throws CMCMessageException {
    try {
      final PKCS10CertificationRequest pkcs10Request =
          new PKCS10CertificationRequest(certificationRequest.getEncoded(ASN1Encoding.DER));
      final PublicKey publicKey = this.validatePkcs10Signature(pkcs10Request);
      pkcs10Request.getSubject();

      final Attribute[] p10ExtAttributes =
          pkcs10Request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
      final List<ExtensionModel> extensionModelList = new ArrayList<>();
      if (p10ExtAttributes != null && p10ExtAttributes.length > 0) {
        final Attribute attribute = Attribute.getInstance(p10ExtAttributes[0]);
        final ASN1Sequence extSequence = ASN1Sequence.getInstance(attribute.getAttrValues().getObjectAt(0));
        final Iterator<ASN1Encodable> iterator = extSequence.iterator();
        while (iterator.hasNext()) {
          final Extension extension = Extension.getInstance(iterator.next());
          extensionModelList.add(new GenericExtensionModel(
              extension.getExtnId(),
              extension.getParsedValue().toASN1Primitive(),
              extension.isCritical()));
        }
      }

      final CertificateModel certificateModel = CertificateModel.builder()
          .publicKey(publicKey)
          .subject(new EncodedCertNameModel(pkcs10Request.getSubject()))
          .extensionModels(extensionModelList)
          .build();
      return certificateModel;
    }
    catch (IOException | OperatorCreationException | PKCSException e) {
      throw new CMCMessageException("Failed to get certificate model from PKCS#10 - " + e.getMessage(), e);
    }
  }

  private PublicKey validatePkcs10Signature(final PKCS10CertificationRequest pkcs10Request)
      throws CMCMessageException, OperatorCreationException, PKCSException, IOException {
    final JcaContentVerifierProviderBuilder builder = new JcaContentVerifierProviderBuilder().setProvider("BC");
    final boolean signatureValid =
        pkcs10Request.isSignatureValid(builder.build(pkcs10Request.getSubjectPublicKeyInfo()));
    if (signatureValid) {
      return BouncyCastleProvider.getPublicKey(pkcs10Request.getSubjectPublicKeyInfo());
    }
    throw new CMCMessageException("Invalid PKCS10 signature");
  }

}
