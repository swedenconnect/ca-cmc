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
package se.swedenconnect.ca.cmc.auth;

/**
 * Exception related to CMC authorization decisions.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCAuthorizationException extends RuntimeException {

  private static final long serialVersionUID = -2749871697534432294L;

  /**
   * Constructor
   */
  public CMCAuthorizationException() {
  }

  /**
   * Constructor
   *
   * @param message message
   */
  public CMCAuthorizationException(String message) {
    super(message);
  }

  /**
   *
   * @param message message
   * @param cause cause
   */
  public CMCAuthorizationException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructor
   *
   * @param cause cause
   */
  public CMCAuthorizationException(Throwable cause) {
    super(cause);
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   * @param enableSuppression enable suppression
   * @param writableStackTrace writable stack trace
   */
  public CMCAuthorizationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
