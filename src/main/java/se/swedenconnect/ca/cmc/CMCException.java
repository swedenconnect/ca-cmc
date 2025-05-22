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
package se.swedenconnect.ca.cmc;

/**
 * Abstract base class for all CMC-related exceptions.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class CMCException extends Exception {

  /** For serializing. */
  private static final long serialVersionUID = 6135495526825649320L;

  /**
   * Constructor accepting the error message.
   *
   * @param message the error message
   */
  public CMCException(final String message) {
    super(message);
  }

  /**
   * Constructor accepting the cause of the error.
   *
   * @param cause the cause of the error
   */
  public CMCException(final Throwable cause) {
    super(cause);
  }

  /**
   * Constructor accepting the error message and the cause of the error.
   *
   * @param message the error message
   * @param cause the cause of the error
   */
  public CMCException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
