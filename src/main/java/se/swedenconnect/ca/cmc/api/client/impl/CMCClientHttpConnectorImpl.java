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
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;

import org.apache.commons.io.IOUtils;

import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.client.CMCClientHttpConnector;
import se.swedenconnect.ca.cmc.api.client.CMCHttpResponseData;

/**
 * Implementation of the CMC Client HTTP Connector handling communication with the CA service.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@NoArgsConstructor
public class CMCClientHttpConnectorImpl implements CMCClientHttpConnector {

  @Setter
  Proxy proxy;

  private static final String CMC_MIME_TYPE = "application/pkcs7-mime";

  /** {@inheritDoc} */
  @Override
  public CMCHttpResponseData sendCmcRequest(final byte[] cmcRequestBytes, final URL requestUrl,
      final int connectTimeout, final int readTimeout) {
    try {
      final HttpURLConnection connection = proxy == null
        ? (HttpURLConnection) requestUrl.openConnection()
        : (HttpURLConnection) requestUrl.openConnection(proxy);
      connection.setRequestMethod("POST");
      connection.setDoOutput(true);
      connection.setRequestProperty("Content-Type", CMC_MIME_TYPE);
      connection.connect();
      try (OutputStream os = connection.getOutputStream()) {
        os.write(cmcRequestBytes);
      }
      connection.setConnectTimeout(connectTimeout);
      connection.setReadTimeout(readTimeout);
      final int responseCode = connection.getResponseCode();
      byte[] bytes;
      try {
        if (responseCode > 205) {
          bytes = IOUtils.toByteArray(connection.getErrorStream());
        }
        else {
          bytes = IOUtils.toByteArray(connection.getInputStream());
        }
      }
      catch (final IOException ex) {
        log.debug("Error receiving http data stream {}", ex.toString());
        return CMCHttpResponseData.builder()
            .data(null)
            .exception(ex)
            .responseCode(responseCode)
            .build();
      }
      return CMCHttpResponseData.builder()
          .data(bytes)
          .exception(null)
          .responseCode(responseCode)
          .build();
    }
    catch (final Exception ex) {
      log.debug("Error setting up HTTP connection {}", ex.toString());
      return CMCHttpResponseData.builder()
          .data(null)
          .exception(ex)
          .responseCode(0)
          .build();
    }

  }
}
