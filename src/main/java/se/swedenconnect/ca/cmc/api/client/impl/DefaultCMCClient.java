/*
 * Copyright 2022 Agency for Digital Government (DIGG)
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

import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.operator.OperatorCreationException;

import se.swedenconnect.ca.cmc.CMCException;
import se.swedenconnect.ca.cmc.api.client.CMCResponseExtract;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.response.StaticCAInformation;
import se.swedenconnect.ca.cmc.model.request.impl.CMCAdminRequestModel;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Implements the CMC Client used to execute CA management operations via CMC on a remote CA
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCMCClient extends AbstractCMCClient {

  /**
   * Constructor for the CMC Client
   *
   * @param cmcRequestUrl URL where CMC requests are sent to the remote CA
   * @param cmcClientCredential the private key and certificate for the CMC client
   * @param algorithm CMC signing algorithm
   * @param cmcResponseCert signing certificate of the remote CA CMC responder
   * @param caCertificate CA certificate used by the remote CA to issue certificates
   * @throws MalformedURLException malformed URL
   * @throws NoSuchAlgorithmException algorithm is not supported or recognized
   * @throws OperatorCreationException error setting up CMC client
   * @throws CertificateEncodingException error parsing provided certificates
   */
  public DefaultCMCClient(final String cmcRequestUrl, final PkiCredential cmcClientCredential, final String algorithm,
      final X509Certificate cmcResponseCert, final X509Certificate caCertificate)
      throws MalformedURLException, NoSuchAlgorithmException, OperatorCreationException, CertificateEncodingException {
    super(cmcRequestUrl, cmcClientCredential, algorithm, cmcResponseCert, caCertificate);
  }

  @Override
  public StaticCAInformation getStaticCAInformation() throws CMCException {
    final CMCRequest cmcRequest = this.cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
        .adminRequestType(AdminRequestType.staticCaInfo)
        .build()));
    return CMCResponseExtract.extractStaticCAInformation(this.getCMCResponse(cmcRequest));
  }

}
