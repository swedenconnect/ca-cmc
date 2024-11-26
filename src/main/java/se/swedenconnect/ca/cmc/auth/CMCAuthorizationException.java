/*
 * Copyright 2024 Agency for Digital Government (DIGG)
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

import se.swedenconnect.ca.cmc.CMCException;

/**
 * Exception related to CMC authorization decisions.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCAuthorizationException extends CMCException {

  private static final long serialVersionUID = -2749871697534432294L;

  /**
   * Constructor
   *
   * @param message message
   */
  public CMCAuthorizationException(final String message) {
    super(message);
  }

  /**
   *
   * @param message message
   * @param cause cause
   */
  public CMCAuthorizationException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructor
   *
   * @param cause cause
   */
  public CMCAuthorizationException(final Throwable cause) {
    super(cause);
  }

}
