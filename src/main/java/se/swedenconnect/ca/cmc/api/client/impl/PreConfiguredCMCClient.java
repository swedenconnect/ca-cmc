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
package se.swedenconnect.ca.cmc.api.client.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.operator.OperatorCreationException;

import se.swedenconnect.ca.cmc.model.admin.response.StaticCAInformation;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Implements a pre-configured CMC Client that never needs to ask the CA for its static information.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PreConfiguredCMCClient extends AbstractCMCClient {

  /**
   * This static information MUST contain:
   *
   * <ul>
   * <li>CA certificate (first item in ca chain list)</li>
   * <li>CA signing algorithm URI</li>
   * <li>CRL distribution point URL(s)</li>
   * <li>OCSP responder URL if OCSP is used</li>
   * </ul>
   *
   * <p>
   * Inclusion of the OCSP certificate is optional even if OCSP is used. Leaving it out just means that a request to the
   * API for static CA information will not return information about OCSP certificate. If that is not used byt eh
   * application using this API, the OCSP certificate can be omitted
   * </p>
   */
  private final StaticCAInformation staticCaInformation;

  /**
   * Constructor for the CMC Client
   *
   * @param cmcRequestUrl URL where CMC requests are sent to the remote CA
   * @param cmcClientCredential the private key and certificate for the CMC client
   * @param algorithm CMC signing algorithm
   * @param cmcResponseCert signing certificate of the remote CA CMC responder
   * @param staticCaInformation Static information about the issuing CA
   * @throws MalformedURLException malformed URL
   * @throws NoSuchAlgorithmException algorithm is not supported or recognized
   * @throws OperatorCreationException error setting up CMC client
   * @throws CertificateEncodingException error parsing provided certificates
   */
  public PreConfiguredCMCClient(final String cmcRequestUrl, final PkiCredential cmcClientCredential,
      final String algorithm, final X509Certificate cmcResponseCert,
      final StaticCAInformation staticCaInformation)
      throws MalformedURLException, NoSuchAlgorithmException, OperatorCreationException, CertificateEncodingException {
    super(cmcRequestUrl, cmcClientCredential, algorithm, cmcResponseCert,
        getX509Cert(staticCaInformation.getCertificateChain().get(0)));
    this.staticCaInformation = staticCaInformation;
  }

  /**
   * Convert certificate bytes to certificate holder in a way that matches the constructor
   *
   * @param certBytes certificate bytes
   * @return {@link X509Certificate}
   * @throws CertificateEncodingException on errors parsing the certificate
   */
  private static X509Certificate getX509Cert(final byte[] certBytes) throws CertificateEncodingException {
    try (InputStream inStream = new ByteArrayInputStream(certBytes)) {
      final CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(inStream);
    }
    catch (IOException | CertificateException e) {
      throw new CertificateEncodingException(e);
    }
  }

  @Override
  public StaticCAInformation getStaticCAInformation() {
    return this.staticCaInformation;
  }

}
