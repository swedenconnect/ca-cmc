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
package se.swedenconnect.ca.cmc.api.data;

import java.util.List;

import org.bouncycastle.asn1.cmc.BodyPartID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data class for CMC response status information
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CMCResponseStatus {

  /** The major status indicating success or failure */
  private CMCStatusType status;

  /** Detailed failure information as provided by {@link CMCFailType} */
  private CMCFailType failType;

  /** Status message, normally null on success responses */
  private String message;

  /** List of request control message body part ID:s that was processed in the request to obtain the response */
  private List<BodyPartID> bodyPartIDList;

  /**
   * Constructor
   *
   * @param status status type indication
   * @param bodyPartIDList list of BodyPartID of controls that caused the status indication
   */
  public CMCResponseStatus(final CMCStatusType status, final List<BodyPartID> bodyPartIDList) {
    this.status = status;
    this.bodyPartIDList = bodyPartIDList;
  }

}
