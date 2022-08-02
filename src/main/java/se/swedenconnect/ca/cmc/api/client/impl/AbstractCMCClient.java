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

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.swedenconnect.ca.cmc.api.CMCCertificateModelBuilder;
import se.swedenconnect.ca.cmc.api.CMCRequestFactory;
import se.swedenconnect.ca.cmc.api.CMCResponseParser;
import se.swedenconnect.ca.cmc.api.client.CMCClient;
import se.swedenconnect.ca.cmc.api.client.CMCClientHttpConnector;
import se.swedenconnect.ca.cmc.api.client.CMCHttpResponseData;
import se.swedenconnect.ca.cmc.api.client.CMCResponseExtract;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.auth.impl.DefaultCMCValidator;
import se.swedenconnect.ca.cmc.model.admin.AdminCMCData;
import se.swedenconnect.ca.cmc.model.admin.AdminRequestType;
import se.swedenconnect.ca.cmc.model.admin.request.ListCerts;
import se.swedenconnect.ca.cmc.model.admin.response.CAInformation;
import se.swedenconnect.ca.cmc.model.admin.response.StaticCAInformation;
import se.swedenconnect.ca.cmc.model.request.impl.CMCAdminRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCCertificateRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCGetCertRequestModel;
import se.swedenconnect.ca.cmc.model.request.impl.CMCRevokeRequestModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Abstract implementation of a CMC Client used to execute CA management operations via CMC on a remote CA
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractCMCClient implements CMCClient {

  protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  protected final CMCRequestFactory cmcRequestFactory;
  protected final CMCResponseParser cmcResponseParser;
  protected CAInformation cachedCAInformation;
  protected Date lastCAInfoRecache;
  protected final URL cmcRequestUrl;
  protected final X509Certificate caCertificate;

  @Setter protected int connectTimeout = 1000;
  @Setter protected int readTimeout = 5000;
  @Setter protected int timeSkew = 60000;
  @Setter protected int maxAge = 60000;
  @Setter protected int caInfoMaxAge = 600000;
  @Setter protected CMCClientHttpConnector cmcClientHttpConnector;

  /**
   * Constructor for the CMC Client
   *
   * @param cmcRequestUrl URL where CMC requests are sent to the remote CA
   * @param cmcSigningKey CMC client signing key
   * @param cmcSigningCert CMC client signing certificate
   * @param algorithm CMC signing algorithm
   * @param cmcResponseCert signing certificate of the remote CA CMC responder
   * @param caCertificate CA certificate used by the remote CA to issue certificates
   * @throws MalformedURLException malformed URL
   * @throws NoSuchAlgorithmException algorithm is not supported or recognized
   * @throws OperatorCreationException error setting up CMC client
   * @throws CertificateEncodingException error parsing provided certificates
   */
  public AbstractCMCClient(String cmcRequestUrl, PrivateKey cmcSigningKey, X509Certificate cmcSigningCert, String algorithm,
    X509Certificate cmcResponseCert, X509Certificate caCertificate)
    throws MalformedURLException, NoSuchAlgorithmException, OperatorCreationException, CertificateEncodingException {
    this.cmcRequestUrl = new URL(cmcRequestUrl);
    ContentSigner contentSigner = new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(algorithm)).build(cmcSigningKey);
    this.cmcRequestFactory = new CMCRequestFactory(List.of(cmcSigningCert), contentSigner);
    this.caCertificate = caCertificate;
    this.cmcResponseParser = new CMCResponseParser(new DefaultCMCValidator(cmcResponseCert), caCertificate.getPublicKey());
    this.cmcClientHttpConnector = new CMCClientHttpConnectorImpl();
  }

  /**
   * Request a list of all certificate serial numbers in the current CA repository
   *
   * @return CMC response with certificate serial numbers or appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  @Override public CMCResponse getAllCertSerialNumbers() throws IOException {
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
      .adminRequestType(AdminRequestType.allCertSerials)
      .build()));

    return getCMCResponse(cmcRequest);
  }

  /**
   * Send a request to issue a certificate
   *
   * @param certificateModel certificate model describing the content of the certificate to be issued
   * @return CMC response with issued certificate or appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  @Override public CMCResponse issueCertificate(CertificateModel certificateModel) throws IOException {
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCCertificateRequestModel(certificateModel, "crmf"));
    return getCMCResponse(cmcRequest);
  }

  /**
   * Send a request to retrieve a particular certificate
   *
   * @param serialNumber serial number of the certificate to retrieve
   * @return CMC response with the retrieved certificate or appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  @Override public CMCResponse getIssuedCertificate(BigInteger serialNumber) throws IOException {
    X509CertificateHolder caIssuerCert = getCertificateHolder(caCertificate);
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCGetCertRequestModel(serialNumber, caIssuerCert.getSubject()));
    return getCMCResponse(cmcRequest);
  }

  /**
   * Send a request to revoke a certificate
   *
   * @param serialNumber the serial number of the certificate to revoke
   * @param reason the reason code for the revocation
   * @param revocationDate the date of revocation
   * @return CMC response with appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  @Override public CMCResponse revokeCertificate(BigInteger serialNumber, int reason, Date revocationDate) throws IOException {
    X509CertificateHolder caIssuerCert = getCertificateHolder(caCertificate);
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCRevokeRequestModel(
      serialNumber,
      reason,
      revocationDate,
      caIssuerCert.getSubject()
    ));
    return getCMCResponse(cmcRequest);
  }

  /**
   * Send a request to list a range of certificates in the CA repository. This function divide certificates into
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
  @Override public CMCResponse listCertificates(int pageSize, int pageIndex, SortBy sortBy, boolean notRevoked,
    boolean descending) throws IOException {
    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
      .adminRequestType(AdminRequestType.listCerts)
      .data(OBJECT_MAPPER.writeValueAsString(ListCerts.builder()
        .pageSize(pageSize)
        .pageIndex(pageIndex)
        .sortBy(sortBy)
        .notRevoked(notRevoked)
          .descending(descending)
        .build()))
      .build()));
    return getCMCResponse(cmcRequest);
  }

  /**
   * Return a certificate model builder prepared for creating certificate models for certificate requests to this CA service via CMC
   *
   * @param subjectPublicKey the public key of the subject
   * @param subject          subject name data
   * @param includeCrlDPs    true to include CRL distribution point URLs in the issued certificate
   * @param includeOcspURL   true to include OCSP URL (if present) in the issued certificate
   * @return certificate model builder
   * @throws IOException errors obtaining the certificate model builder
   */
  @Override public CMCCertificateModelBuilder getCertificateModelBuilder(PublicKey subjectPublicKey,
    CertNameModel<?> subject,
    boolean includeCrlDPs, boolean includeOcspURL) throws IOException {
    final StaticCAInformation caInformation = getStaticCAInformation();
    X509CertificateHolder caIssuerCert = getCertificateHolder(caCertificate);
    CMCCertificateModelBuilder certModelBuilder = CMCCertificateModelBuilder.getInstance(subjectPublicKey, caIssuerCert,
      caInformation.getCaAlgorithm());

    if (includeCrlDPs) {
      certModelBuilder.crlDistributionPoints(caInformation.getCrlDpURLs());
    }
    if (includeOcspURL) {
      certModelBuilder.ocspServiceUrl(caInformation.getOcspResponserUrl());
    }
    certModelBuilder.subject(subject);
    return certModelBuilder;
  }

  /**
   * Send a CMC request to obtain information about the remote CA
   *
   * @param forceRecache set to true to force this request to be sent and processed by the remote CA and set to false to
   *                     allow the API to return cached information if it is reasonably fresh
   * @return CA information about the remote CA
   * @throws IOException on error processing the request
   */
  @Override public CAInformation getCAInformation(boolean forceRecache) throws IOException {
    if (!forceRecache) {
      if (this.cachedCAInformation != null && lastCAInfoRecache != null) {
        Date notBefore = new Date(System.currentTimeMillis() - caInfoMaxAge);
        if (lastCAInfoRecache.after(notBefore)) {
          // Re-cache is not forced and current cache is not too old. Use it.
          return cachedCAInformation;
        }
      }
    }
    // Re-cache is required
    cachedCAInformation = CMCResponseExtract.extractCAInformation(getCaInfo());
    lastCAInfoRecache = new Date();
    return cachedCAInformation;
  }


  /**
   * Request information about the remote CA
   *
   * @return CMC response with CA information or appropriate status information
   * @throws IOException error processing the request or communicating with the remote CA
   */
  protected CMCResponse getCaInfo() throws IOException {

    final CMCRequest cmcRequest = cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
      .adminRequestType(AdminRequestType.caInfo)
      .build()));

    return getCMCResponse(cmcRequest);
  }

  protected CMCResponse getCMCResponse(CMCRequest cmcRequest) throws IOException {

    CMCHttpResponseData httpResponseData = cmcClientHttpConnector.sendCmcRequest(cmcRequest.getCmcRequestBytes(), cmcRequestUrl, connectTimeout, readTimeout);
    if (httpResponseData.getResponseCode() > 205 || httpResponseData.getException() != null){
      throw new IOException("Http connection to CA failed");
    }
    byte[] cmcResponseBytes = httpResponseData.getData();
    Date notBefore = new Date(System.currentTimeMillis() - maxAge);
    Date notAfter = new Date(System.currentTimeMillis() + timeSkew);
    final Date signingTime;
    try {
      signingTime = CMCUtils.getSigningTime(cmcResponseBytes);
      if (signingTime.before(notBefore)) {
        throw new IOException("CMC Response is to old");
      }
      if (signingTime.after(notAfter)) {
        throw new IOException("CMC Response is predated - possible time skew problem");
      }
    }
    catch (CMSException e) {
      throw new IOException("Error parsing signing time in CMC Response", e);
    }

    CMCResponse cmcResponse = cmcResponseParser.parseCMCresponse(cmcResponseBytes, cmcRequest.getCmcRequestType());
    if (!Arrays.equals(cmcRequest.getNonce(), cmcResponse.getNonce())) {
      throw new IOException("CMC response and request nonce mismatch");
    }
    return cmcResponse;

  }

  protected X509CertificateHolder getCertificateHolder(X509Certificate caCertificate) throws IOException {
    try {
      return new JcaX509CertificateHolder(caCertificate);
    }
    catch (CertificateEncodingException e) {
      throw new IOException(e);
    }
  }



}
