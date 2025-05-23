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
package se.swedenconnect.ca.cmc.api.data;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.cmc.PKIResponse;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;

/**
 * Data class for CMC response data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CMCResponse {

  /** The type of request this response is responding to */
  private CMCRequestType cmcRequestType;

  /** the bytes of the CMC Response */
  private byte[] cmcResponseBytes;

  /** the response nonce value */
  private byte[] nonce;

  /** the certificates returned in the response except for the CMS signing certificates */
  private List<X509Certificate> returnCertificates;

  /** The PKIResponse data of the response */
  private PKIResponse pkiResponse;

  /** Response status of the response */
  private CMCResponseStatus responseStatus;

}
