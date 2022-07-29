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
 * Exception thrown during CMC validation
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCValidationException extends RuntimeException {

  private static final long serialVersionUID = -7894074545287404113L;

  /**
   * Constructor
   */
  public CMCValidationException() {
  }

  /**
   * Constructor
   *
   * @param message message
   */
  public CMCValidationException(String message) {
    super(message);
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   */
  public CMCValidationException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructor
   *
   * @param cause cause
   */
  public CMCValidationException(Throwable cause) {
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
  public CMCValidationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
