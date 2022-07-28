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
package se.swedenconnect.ca.cmc.api;

import lombok.Getter;

import java.io.IOException;

/**
 * Exception for errors parsing CMC data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class CMCParsingException extends IOException {

  private static final long serialVersionUID = 6145163073622794784L;

  /**
   * Nonce data of the CMC object
   */
  @Getter private final byte[] nonce;

  /**
   * Constructor
   *
   * @param nonce nonce
   */
  public CMCParsingException(byte[] nonce) {
    this.nonce = nonce;
  }

  /**
   * Constructor
   *
   * @param message message
   * @param nonce nonce
   */
  public CMCParsingException(String message, byte[] nonce) {
    super(message);
    this.nonce = nonce;
  }

  /**
   * Constructor
   *
   * @param message message
   * @param cause cause
   * @param nonce nonce
   */
  public CMCParsingException(String message, Throwable cause, byte[] nonce) {
    super(message, cause);
    this.nonce = nonce;
  }

  /**
   * Constructor
   *
   * @param cause cause
   * @param nonce nonce
   */
  public CMCParsingException(Throwable cause, byte[] nonce) {
    super(cause);
    this.nonce = nonce;
  }
}
