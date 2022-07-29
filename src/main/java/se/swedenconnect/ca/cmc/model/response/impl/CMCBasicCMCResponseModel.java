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
package se.swedenconnect.ca.cmc.model.response.impl;

import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.engine.utils.CAUtils;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Generic CMC response model for creating CMC responses
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCBasicCMCResponseModel extends AbstractCMCResponseModel {

  /**
   * Constructor
   *
   * @param nonce nonce
   * @param cmcResponseStatus response status
   * @param cmcRequestType request type
   * @param responseInfo custom response data
   */
  public CMCBasicCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, CMCRequestType cmcRequestType, byte[] responseInfo) {
    super(nonce, cmcResponseStatus, cmcRequestType, responseInfo);
  }

  /**
   * Constructor
   *
   * @param nonce nonce
   * @param cmcResponseStatus response status
   * @param cmcRequestType request type
   * @param responseInfo custom response data
   * @param returnCertificates return certificates
   * @throws CertificateException error parsing certificate data
   * @throws IOException error parsing custom response data
   */
  public CMCBasicCMCResponseModel(byte[] nonce, CMCResponseStatus cmcResponseStatus, CMCRequestType cmcRequestType, byte[] responseInfo, List<?> returnCertificates)
    throws CertificateException, IOException {
    super(nonce, cmcResponseStatus, cmcRequestType, responseInfo);
    addCertificates(returnCertificates);
  }

  private void addCertificates(List<?> returnCertificates) throws CertificateException, IOException {
    List<X509Certificate> certDataList = new ArrayList<>();
    for (Object o : returnCertificates){
      if (o instanceof X509Certificate) {
        certDataList.add((X509Certificate)o);
        continue;
      }
      if (o instanceof X509CertificateHolder) {
        certDataList.add(CAUtils.getCert((X509CertificateHolder)o));
        continue;
      }
      throw new IOException("Illegal certificate type");
    }
    setReturnCertificates(certDataList);
  }

}
