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
package se.swedenconnect.ca.cmc.api.client;

import java.net.Proxy;
import java.net.URL;

/**
 * interface for a connector that is responsible for sending and receiving data from the CA
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCClientHttpConnector {

  /**
   * Sending a request to a CA and getting a CMC response back or relevant error data
   *
   * @param cmcRequestBytes CMC request data
   * @param requestUrl URL used to send the request
   * @param connectTimeout the timeout for http connect specified in milliseconds
   * @param readTimeout the timeout for reading http data specified in milliseconds
   * @return response data
   */
  CMCHttpResponseData sendCmcRequest(final byte[] cmcRequestBytes, final URL requestUrl,
      final int connectTimeout, final int readTimeout);

}
