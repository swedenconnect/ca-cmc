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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.AuthorityKeyIdentifierModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.SubjectKeyIdentifierModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

/**
 * Default certificate model builder implementation
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMCCertificateModelBuilder extends AbstractCertificateModelBuilder<CMCCertificateModelBuilder> {

  /** Subject public key */
  private final PublicKey publicKey;

  /** Certificate of the issuer */
  private final X509CertificateHolder issuer;

  /**
   * Algorithm used by the CA to sign certificates. This is used to identify the hash algorithm used to hash key
   * identifiers
   */
  private final String caAlgorithm;

  /**
   * Private constructor
   *
   * @param publicKey subject public key
   * @param issuer issuer certificate
   * @param caAlgorithm certificate signing algorithm
   */
  private CMCCertificateModelBuilder(
      final PublicKey publicKey, final X509CertificateHolder issuer, final String caAlgorithm) {
    this.publicKey = publicKey;
    this.issuer = issuer;
    this.caAlgorithm = caAlgorithm;
  }

  /**
   * Creates an instance of this certificate model builder
   *
   * @param publicKey subject public key
   * @param issuer issuer certificate
   * @param caAlgorithm certificate signing algorithm
   * @return certificate model builder
   */
  public static CMCCertificateModelBuilder getInstance(
      final PublicKey publicKey, final X509CertificateHolder issuer, final String caAlgorithm) {
    return new CMCCertificateModelBuilder(publicKey, issuer, caAlgorithm);
  }

  /** {@inheritDoc} */
  @Override
  protected PublicKey getPublicKey() {
    return this.publicKey;
  }

  @Override
  protected void getKeyIdentifierExtensionsModels(final List<ExtensionModel> extm) throws IOException {

    // Authority key identifier
    if (this.includeAki) {
      AuthorityKeyIdentifierModel akiModel = null;
      try {
        final byte[] kidVal =
            SubjectKeyIdentifier.getInstance(this.issuer.getExtension(Extension.subjectKeyIdentifier).getParsedValue())
                .getKeyIdentifier();
        if (kidVal != null && kidVal.length > 0) {
          akiModel = new AuthorityKeyIdentifierModel(new AuthorityKeyIdentifier(kidVal));
        }
      }
      catch (final Exception ignored) {
      }

      if (akiModel == null) {
        akiModel = new AuthorityKeyIdentifierModel(new AuthorityKeyIdentifier(
            this.getSigAlgoMessageDigest(this.caAlgorithm).digest(this.issuer.getSubjectPublicKeyInfo().getEncoded())));
      }
      extm.add(akiModel);
    }

    // Subject key identifier
    if (this.includeSki) {
      extm.add(new SubjectKeyIdentifierModel(
          this.getSigAlgoMessageDigest(this.caAlgorithm).digest(this.publicKey.getEncoded())));
    }

  }

  /**
   * Returns an instance of {@link MessageDigest} specified by the certificate signature algorithm
   *
   * @return message digest instance
   */
  private MessageDigest getSigAlgoMessageDigest(final String algorithm) {
    MessageDigest messageDigestInstance = null;
    try {
      messageDigestInstance = CAAlgorithmRegistry.getMessageDigestInstance(algorithm);
    }
    catch (final NoSuchAlgorithmException e) {
      log.error("Illegal configured signature algorithm prevents retrieval of signature algorithm digest algorithm", e);
    }
    return messageDigestInstance;
  }

}
