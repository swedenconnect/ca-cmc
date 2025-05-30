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
package se.swedenconnect.ca.cmc.auth;

import org.bouncycastle.cms.CMSSignedData;

/**
 * Interface for implementation of a replay checker used by the CMC parser to determine if a CMC request is new and not
 * a replay of an old request.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CMCReplayChecker {

  /**
   * Validates a CMC request against replay according to a defined policy
   *
   * @param cmsSignedData the signed CMC request data
   * @throws CMCReplayException if a violation of the replay protection policy is detected
   */
  void validate(final CMSSignedData cmsSignedData) throws CMCReplayException;

}
