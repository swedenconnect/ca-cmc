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

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.client.CMCClientHttpConnector;
import se.swedenconnect.ca.cmc.api.client.CMCHttpResponseData;

/**
 * CMC client HTTP Connector
 */
@Slf4j
public class ProxyCMCClientHttpConnector implements CMCClientHttpConnector {

  /** Mime type for CMC messages */
  private static final String CMC_MIME_TYPE = "application/pkcs7-mime";

  /** The Http client used to send cmc requests */
  private final HttpClient httpClient;

  /**
   * Constructor for this CMC client http connector
   *
   * @param cmcClientProxyConfig optional proxy configuration data (null to select no proxy)
   */
  public ProxyCMCClientHttpConnector(final HttpProxyConfiguration cmcClientProxyConfig) {
    this.httpClient = createHttpClient(cmcClientProxyConfig);
  }

  /** {@inheritDoc} */
  @Override public CMCHttpResponseData sendCmcRequest(final byte[] cmcRequestBytes, final URL requestUrl,
    final int connectTimeout, final int readTimeout) {

    final HttpPost request;

    try {
      request = new HttpPost(requestUrl.toURI());
      request.addHeader("Content-Type", CMC_MIME_TYPE);
      request.setEntity(new ByteArrayEntity(cmcRequestBytes));
      request.setConfig(RequestConfig.custom()
        .setConnectTimeout(connectTimeout)
        .setConnectionRequestTimeout(connectTimeout)
        .setSocketTimeout(readTimeout)
        .build());
    }
    catch (URISyntaxException e) {
      throw new IllegalArgumentException("Bad URL syntax for CMC request");
    }

    try {
      HttpResponse httpResponse = httpClient.execute(request);
      byte[] responseData = IOUtils.toByteArray(httpResponse.getEntity().getContent());
      return CMCHttpResponseData.builder()
        .data(responseData)
        .exception(null)
        .responseCode(httpResponse.getStatusLine().getStatusCode())
        .build();
    }
    catch (IOException ex) {
      log.debug("Error receiving http data stream {}", ex.toString());
      return CMCHttpResponseData.builder()
        .data(null)
        .exception(ex)
        .responseCode(HttpStatus.SC_INTERNAL_SERVER_ERROR)
        .build();
    }
  }

  /**
   * Creates a HTTP client to use.
   *
   * @return a HttpClient
   */
  protected HttpClient createHttpClient(final HttpProxyConfiguration cmcClientProxyConfig) {
    try {
      final HttpClientBuilder builder = HttpClientBuilder.create();
      if (cmcClientProxyConfig != null && cmcClientProxyConfig.getHost() != null) {
        final HttpHost proxy = new HttpHost(cmcClientProxyConfig.getHost(), cmcClientProxyConfig.getPort());
        builder.setProxy(proxy);
        if (cmcClientProxyConfig.getUserName() != null) {
          CredentialsProvider credentialsPovider = new BasicCredentialsProvider();
          credentialsPovider.setCredentials(new AuthScope(proxy), new UsernamePasswordCredentials(
            cmcClientProxyConfig.getUserName(), cmcClientProxyConfig.getPassword()));
          builder.setDefaultCredentialsProvider(credentialsPovider);
        }
      }
      return builder
        .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
        .build();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to initialize HttpClient", e);
    }
  }
}
