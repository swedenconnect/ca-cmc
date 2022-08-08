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

package se.swedenconnect.ca.cmc.api.client;

import lombok.Setter;
import se.swedenconnect.ca.cmc.api.CMCCertificateModelBuilder;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.StaticCAInformation;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.repository.SortBy;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;

/**
 * Interface for a CMC API client used to perform operations on a remote CA using CMC.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCClient {

  /**
   * Obtain information about the remote CA
   *
   * @param forceRecache set to true to force this request to be sent and processed by the remote CA and set to false to
   * allow the API to return cached information if it is reasonably fresh
   * @return CA information about the remote CA
   * @throws IOException on error processing the request
   */
  CAInformation getCAInformation(boolean forceRecache) throws IOException;

  /**
   * Obtain static information about the remote CA.
   * This only include static non changing information about the CA and does not include dynamic changing information
   * such as certificate count.
   *
   * @return static CA information about the remote CA
   * @throws IOException on error processing the request
   */
  StaticCAInformation getStaticCAInformation() throws IOException;

  /**
   * Get a list of all certificate serial numbers in the current CA repository
   *
   * @return CMC response with certificate serial numbers or appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  CMCResponse getAllCertSerialNumbers() throws IOException;

  /**
   * Issue a certificate
   *
   * @param certificateModel certificate model describing the content of the certificate to be issued
   * @return CMC response with issued certificate or appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  CMCResponse issueCertificate(CertificateModel certificateModel) throws IOException;

  /**
   * Retrieve a particular certificate
   *
   * @param serialNumber serial number of the certificate to retrieve
   * @return CMC response with the retrieved certificate or appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  CMCResponse getIssuedCertificate(BigInteger serialNumber) throws IOException;

  /**
   * Revoke a certificate
   *
   * @param serialNumber the serial number of the certificate to revoke
   * @param reason the reason code for the revocation
   * @param revocationDate the date of revocation
   * @return CMC response with appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  CMCResponse revokeCertificate(BigInteger serialNumber, int reason, Date revocationDate) throws IOException;

  /**
   * List a range of certificates in the CA repository. This function divide certificates into
   * pages with a fixed amount of certificates in each page. This function allows to retrieve a page of certificates
   * and to specify the conditions for constructing this page.
   *
   * @param pageSize the number of certificates in each page
   * @param pageIndex the index of the page of the requested size to return
   * @param sortBy indication of whether pages of certificates should be sorted by issue date or serial number
   * @param notRevoked tue to exclude all revoked certificates from the pages of certificates
   * @param descending true to use descending sorting order
   * @return the identified page of certificates
   * @throws IOException on error processing the request
   */
  CMCResponse listCertificates(int pageSize, int pageIndex, SortBy sortBy, boolean notRevoked,
    boolean descending) throws IOException;

  /**
   * Return a certificate model builder prepared for creating certificate models for certificate requests to this CA service via CMC
   *
   * @param subjectPublicKey the public key of the subject
   * @param subject subject name data
   * @param includeCrlDPs true to include CRL distribution point URLs in the issued certificate
   * @param includeOcspURL true to include OCSP URL (if present) in the issued certificate
   * @return certificate model builder
   * @throws IOException errors obtaining the certificate model builder
   */
  CMCCertificateModelBuilder getCertificateModelBuilder(PublicKey subjectPublicKey, CertNameModel<?> subject,
    boolean includeCrlDPs, boolean includeOcspURL) throws IOException;

  /**
   * Set HTTP connect timeout in milliseconds.
   *
   * @param connectTimeout HTTP connect timeout in milliseconds
   */
  void setConnectTimeout(int connectTimeout);

  /**
   * Set HTTP read timeout in milliseconds.
   *
   * @param readTimeout HTTP read timeout in milliseconds
   */
  void setReadTimeout(int readTimeout);

  /**
   * Set Max time skew in milliseconds allowed between client and server.
   *
   * @param timeSkew max time skew in milliseconds
   */
  void setTimeSkew(int timeSkew);

  /**
   * Set Max age in milliseconds for an acceptable CMC response (time skew will be added to this time).
   *
   * @param maxAge max age in milliseconds
   */
  void setMaxAge(int maxAge);

  /**
   * Set CA information max age in milliseconds before a re-cache is forced
   *
   * @param caInfoMaxAge CA information max age in milliseconds
   */
  void setCaInfoMaxAge(int caInfoMaxAge);

  /**
   * Set a custom {@link CMCClientHttpConnector}. A default CMC client HTTP connector will be configured if none is set.
   *
   * @param cmcClientHttpConnector CMC client HTTP connector
   */
  void setCmcClientHttpConnector(CMCClientHttpConnector cmcClientHttpConnector);

}
