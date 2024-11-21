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
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;

import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.ssl.SSLContextBuilder;
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
  private final CloseableHttpClient httpClient;

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
      request.setEntity(new ByteArrayEntity(cmcRequestBytes, ContentType.create(CMC_MIME_TYPE)));
      request.setConfig(RequestConfig.custom()
          .setConnectionRequestTimeout(connectTimeout, TimeUnit.MILLISECONDS)
          .setResponseTimeout(readTimeout, TimeUnit.MILLISECONDS)
        .build());
    }
    catch (URISyntaxException e) {
      throw new IllegalArgumentException("Bad URL syntax for CMC request");
    }

    try {
      CloseableHttpResponse httpResponse = httpClient.execute(request);
      byte[] responseData = IOUtils.toByteArray(httpResponse.getEntity().getContent());
      return CMCHttpResponseData.builder()
        .data(responseData)
        .exception(null)
        .responseCode(httpResponse.getCode())
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
  protected CloseableHttpClient createHttpClient(final HttpProxyConfiguration cmcClientProxyConfig) {
    try {
      final HttpClientBuilder builder = HttpClientBuilder.create();
      if (cmcClientProxyConfig != null && cmcClientProxyConfig.getHost() != null) {
        final HttpHost proxy = new HttpHost(cmcClientProxyConfig.getHost(), cmcClientProxyConfig.getPort());
        builder.setProxy(proxy);
        if (cmcClientProxyConfig.getUserName() != null) {
          final char[] password =
            cmcClientProxyConfig.getPassword() == null ? null : cmcClientProxyConfig.getPassword().toCharArray();
          final BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
          credentialsProvider.setCredentials(new AuthScope(proxy), new UsernamePasswordCredentials(
            cmcClientProxyConfig.getUserName(), password));
          builder.setDefaultCredentialsProvider(credentialsProvider);
        }
      }
      return builder.setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
          .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
            .setSslContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
            .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
            .build()).build())
        .build();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to initialize HttpClient", e);
    }
  }
}
