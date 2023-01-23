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

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.ca.cmc.CMCException;
import se.swedenconnect.ca.cmc.api.CMCCertificateModelBuilder;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
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
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Abstract implementation of a CMC Client used to execute CA management operations via CMC on a remote CA
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractCMCClient implements CMCClient {

  /** JSON data object mapper */
  protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  /** {@inheritDoc} */
  @Setter
  protected int connectTimeout = 1000;

  /** {@inheritDoc} */
  @Setter
  protected int readTimeout = 5000;

  /** {@inheritDoc} */
  @Setter
  protected int timeSkew = 60000;

  /** {@inheritDoc} */
  @Setter
  protected int maxAge = 60000;

  /** {@inheritDoc} */
  @Setter
  protected int caInfoMaxAge = 600000;

  /** {@inheritDoc} */
  @Setter @Getter
  protected CMCClientHttpConnector cmcClientHttpConnector;

  /** Cached CA information */
  protected CAInformation cachedCAInformation;

  /** Time when last CA information was cached */
  protected Date lastCAInfoRecache;

  /** CMC request factory */
  protected final CMCRequestFactory cmcRequestFactory;

  /** CMC response parser */
  protected final CMCResponseParser cmcResponseParser;

  /** CMC Request URL where CMC requests are sent */
  protected final URL cmcRequestUrl;

  /** CA issuer certificate */
  protected final X509Certificate caCertificate;

  /**
   * Constructor for the CMC Client.
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
  public AbstractCMCClient(final String cmcRequestUrl, final PkiCredential cmcClientCredential,
      final String algorithm, final X509Certificate cmcResponseCert, final X509Certificate caCertificate)
      throws MalformedURLException, OperatorCreationException, NoSuchAlgorithmException, CertificateEncodingException {

    if (Objects.requireNonNull(cmcClientCredential, "cmcClientCredential must not be null").getCertificate() == null) {
      throw new IllegalArgumentException("Invalid CMC client credential - missing certificate");
    }

    this.cmcRequestUrl = new URL(cmcRequestUrl);
    final ContentSigner contentSigner =
        new JcaContentSignerBuilder(CAAlgorithmRegistry.getSigAlgoName(algorithm))
            .build(cmcClientCredential.getPrivateKey());
    this.cmcRequestFactory = new CMCRequestFactory(List.of(cmcClientCredential.getCertificate()), contentSigner);
    this.caCertificate = caCertificate;
    this.cmcResponseParser =
        new CMCResponseParser(new DefaultCMCValidator(cmcResponseCert), caCertificate.getPublicKey());
    this.cmcClientHttpConnector = new CMCClientHttpConnectorImpl();
  }

  /**
   * Request a list of all certificate serial numbers in the current CA repository
   *
   * @return CMC response with certificate serial numbers or appropriate status information
   * @throws CMCException error processing the request or communicating with the remote CA
   */
  @Override
  public CMCResponse getAllCertSerialNumbers() throws CMCException {
    final CMCRequest cmcRequest = this.cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
        .adminRequestType(AdminRequestType.allCertSerials)
        .build()));

    return this.getCMCResponse(cmcRequest);
  }

  /**
   * Send a request to issue a certificate
   *
   * @param certificateModel certificate model describing the content of the certificate to be issued
   * @return CMC response with issued certificate or appropriate status information
   * @throws CMCException error processing the request or communicating with the remote CA
   */
  @Override
  public CMCResponse issueCertificate(final CertificateModel certificateModel) throws CMCException {
    final CMCRequest cmcRequest =
        this.cmcRequestFactory.getCMCRequest(new CMCCertificateRequestModel(certificateModel, "crmf"));
    return this.getCMCResponse(cmcRequest);
  }

  /**
   * Send a request to retrieve a particular certificate.
   *
   * @param serialNumber serial number of the certificate to retrieve
   * @return CMC response with the retrieved certificate or appropriate status information
   * @throws CMCException error processing the request or communicating with the remote CA
   */
  @Override
  public CMCResponse getIssuedCertificate(final BigInteger serialNumber) throws CMCException {
    final X509CertificateHolder caIssuerCert = this.getCertificateHolder(this.caCertificate);
    final CMCRequest cmcRequest =
        this.cmcRequestFactory.getCMCRequest(new CMCGetCertRequestModel(serialNumber, caIssuerCert.getSubject()));
    return this.getCMCResponse(cmcRequest);
  }

  /**
   * Send a request to revoke a certificate
   *
   * @param serialNumber the serial number of the certificate to revoke
   * @param reason the reason code for the revocation
   * @param revocationDate the date of revocation
   * @return CMC response with appropriate status information
   * @throws CMCException error processing the request or communicating with the remote CA
   */
  @Override
  public CMCResponse revokeCertificate(final BigInteger serialNumber, final int reason, final Date revocationDate)
      throws CMCException {
    final X509CertificateHolder caIssuerCert = this.getCertificateHolder(this.caCertificate);
    final CMCRequest cmcRequest = this.cmcRequestFactory.getCMCRequest(new CMCRevokeRequestModel(
        serialNumber,
        reason,
        revocationDate,
        caIssuerCert.getSubject()));
    return this.getCMCResponse(cmcRequest);
  }

  /**
   * Send a request to list a range of certificates in the CA repository. This function divide certificates into pages
   * with a fixed amount of certificates in each page. This function allows to retrieve a page of certificates and to
   * specify the conditions for constructing this page.
   *
   * @param pageSize the number of certificates in each page
   * @param pageIndex the index of the page of the requested size to return
   * @param sortBy indication of whether pages of certificates should be sorted by issue date or serial number
   * @param notRevoked tue to exclude all revoked certificates from the pages of certificates
   * @param descending true to use descending sorting order
   * @return the identified page of certificates
   * @throws CMCException on error processing the request
   */
  @Override
  public CMCResponse listCertificates(final int pageSize, final int pageIndex, final SortBy sortBy,
      final boolean notRevoked, final boolean descending) throws CMCException {
    try {
      final CMCRequest cmcRequest = this.cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
          .adminRequestType(AdminRequestType.listCerts)
          .data(OBJECT_MAPPER.writeValueAsString(ListCerts.builder()
              .pageSize(pageSize)
              .pageIndex(pageIndex)
              .sortBy(sortBy)
              .notRevoked(notRevoked)
              .descending(descending)
              .build()))
          .build()));
      return this.getCMCResponse(cmcRequest);
    }
    catch (final JsonProcessingException e) {
      throw new CMCMessageException("Failed to write certificates in JSON", e);
    }
  }

  /**
   * Return a certificate model builder prepared for creating certificate models for certificate requests to this CA
   * service via CMC
   *
   * @param subjectPublicKey the public key of the subject
   * @param subject subject name data
   * @param includeCrlDPs true to include CRL distribution point URLs in the issued certificate
   * @param includeOcspURL true to include OCSP URL (if present) in the issued certificate
   * @return certificate model builder
   * @throws CMCException errors obtaining the certificate model builder
   */
  @Override
  public CMCCertificateModelBuilder getCertificateModelBuilder(final PublicKey subjectPublicKey,
      final CertNameModel<?> subject, final boolean includeCrlDPs, final boolean includeOcspURL) throws CMCException {
    final StaticCAInformation caInformation = this.getStaticCAInformation();
    final X509CertificateHolder caIssuerCert = this.getCertificateHolder(this.caCertificate);
    final CMCCertificateModelBuilder certModelBuilder =
        CMCCertificateModelBuilder.getInstance(subjectPublicKey, caIssuerCert,
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
   *          allow the API to return cached information if it is reasonably fresh
   * @return CA information about the remote CA
   * @throws CMCException on error processing the request
   */
  @Override
  public CAInformation getCAInformation(final boolean forceRecache) throws CMCException {
    if (!forceRecache) {
      if (this.cachedCAInformation != null && this.lastCAInfoRecache != null) {
        final Date notBefore = new Date(System.currentTimeMillis() - this.caInfoMaxAge);
        if (this.lastCAInfoRecache.after(notBefore)) {
          // Re-cache is not forced and current cache is not too old. Use it.
          return this.cachedCAInformation;
        }
      }
    }
    // Re-cache is required
    this.cachedCAInformation = CMCResponseExtract.extractCAInformation(this.getCaInfo());
    this.lastCAInfoRecache = new Date();
    return this.cachedCAInformation;
  }

  /**
   * Request information about the remote CA
   *
   * @return CMC response with CA information or appropriate status information
   * @throws CMCException error processing the request or communicating with the remote CA
   */
  protected CMCResponse getCaInfo() throws CMCException {

    final CMCRequest cmcRequest = this.cmcRequestFactory.getCMCRequest(new CMCAdminRequestModel(AdminCMCData.builder()
        .adminRequestType(AdminRequestType.caInfo)
        .build()));

    return this.getCMCResponse(cmcRequest);
  }

  /**
   * Send a CMC request and obtain the corresponding CMC response
   *
   * @param cmcRequest CMC request
   * @return CMC response
   * @throws CMCException error sending or processing CMC request or response
   */
  protected CMCResponse getCMCResponse(final CMCRequest cmcRequest) throws CMCException {

    final CMCHttpResponseData httpResponseData =
        this.cmcClientHttpConnector.sendCmcRequest(cmcRequest.getCmcRequestBytes(),
            this.cmcRequestUrl,
            this.connectTimeout, this.readTimeout);
    if (httpResponseData.getResponseCode() > 205 || httpResponseData.getException() != null) {
      throw new CMCClientConnectionException("Http connection to CA failed");
    }
    final byte[] cmcResponseBytes = httpResponseData.getData();
    final Date notBefore = new Date(System.currentTimeMillis() - this.maxAge);
    final Date notAfter = new Date(System.currentTimeMillis() + this.timeSkew);
    final Date signingTime = CMCUtils.getSigningTime(cmcResponseBytes);
    if (signingTime.before(notBefore)) {
      throw new CMCMessageException("CMC Response is to old");
    }
    if (signingTime.after(notAfter)) {
      throw new CMCMessageException("CMC Response is predated - possible time skew problem");
    }

    final CMCResponse cmcResponse =
        this.cmcResponseParser.parseCMCresponse(cmcResponseBytes, cmcRequest.getCmcRequestType());
    if (!Arrays.equals(cmcRequest.getNonce(), cmcResponse.getNonce())) {
      throw new CMCMessageException("CMC response and request nonce mismatch");
    }
    return cmcResponse;

  }

  private X509CertificateHolder getCertificateHolder(final X509Certificate caCertificate) throws CMCMessageException {
    try {
      return new JcaX509CertificateHolder(caCertificate);
    }
    catch (final CertificateEncodingException e) {
      throw new CMCMessageException("Failed to get encoding of CA certificate");
    }
  }

}
