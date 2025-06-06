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
package se.swedenconnect.ca.cmc.data;

import java.util.List;

import org.bouncycastle.asn1.cmc.BodyPartID;

import lombok.AllArgsConstructor;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;

/**
 * Test response status
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
public enum TestResponseStatus {

  success(CMCResponseStatus.builder()
      .status(CMCStatusType.success)
      .build()), failBadRequest(
          CMCResponseStatus.builder()
              .status(CMCStatusType.failed)
              .failType(CMCFailType.badRequest)
              .message("Bad CMC Request")
              .build());

  private CMCResponseStatus responseStatus;

  public CMCResponseStatus withBodyParts(List<BodyPartID> bodyPartIDList) {
    CMCResponseStatus status = CMCResponseStatus.builder()
        .status(responseStatus.getStatus())
        .failType(responseStatus.getFailType())
        .message(responseStatus.getMessage())
        .bodyPartIDList(bodyPartIDList)
        .build();
    return status;
  }

}
