/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.ca.cmc.model.response;

import java.security.cert.X509Certificate;
import java.util.List;

import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * Interface for the CMC response model specifying data for the CMC response.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCResponseModel {

  /**
   * Gets the request nonce.
   *
   * @return request nonce
   */
  byte[] getNonce();

  /**
   * Gets the registration info data. Each request type identifies the syntax of this parameter.
   *
   * @return registration info data
   */
  byte[] getResponseInfo();

  /**
   * The status of the response.
   *
   * @return cmc response status
   */
  CMCResponseStatus getCmcResponseStatus();

  /**
   * Return certificates for the response.
   *
   * @return list of certificate bytes
   */
  List<X509Certificate> getReturnCertificates();

  /**
   * Return CMC request type for the response.
   *
   * @return CMC request type
   */
  CMCRequestType getCmcRequestType();
}
