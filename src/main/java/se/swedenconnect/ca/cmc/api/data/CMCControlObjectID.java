/*
 * Copyright 2023 Agency for Digital Government (DIGG)
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

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * Enumeration of CMC Control object identifiers
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@AllArgsConstructor
@Slf4j
public enum CMCControlObjectID {

  /** CMC status info */
  statusInfo(CMCObjectIdentifiers.id_cmc_statusInfo),

  /** CMC identification */
  identification(CMCObjectIdentifiers.id_cmc_identification),

  /** CMC identity proof */
  identityProof(CMCObjectIdentifiers.id_cmc_identityProof),

  /** CMC data return */
  dataReturn(CMCObjectIdentifiers.id_cmc_dataReturn),

  /** CMC transaction ID */
  transactionId(CMCObjectIdentifiers.id_cmc_transactionId),

  /** CMC sender nonce */
  senderNonce(CMCObjectIdentifiers.id_cmc_senderNonce),

  /** CMC recipient nonce */
  recipientNonce(CMCObjectIdentifiers.id_cmc_recipientNonce),

  /** CMC add extensions */
  addExtensions(CMCObjectIdentifiers.id_cmc_addExtensions),

  /** CMC encrypted POP */
  encryptedPOP(CMCObjectIdentifiers.id_cmc_encryptedPOP),

  /** CMC decrypted POP */
  decryptedPOP(CMCObjectIdentifiers.id_cmc_decryptedPOP),

  /** CMC LRA POP witness */
  lraPOPWitness(CMCObjectIdentifiers.id_cmc_lraPOPWitness),

  /** Get certificate */
  getCert(CMCObjectIdentifiers.id_cmc_getCert),

  /** Get CRL */
  getCRL(CMCObjectIdentifiers.id_cmc_getCRL),

  /** CMC revoke request */
  revokeRequest(CMCObjectIdentifiers.id_cmc_revokeRequest),

  /** CMC registration info used as extension point for custom requests */
  regInfo(CMCObjectIdentifiers.id_cmc_regInfo),

  /** CMC response info used as extension point for custom response data */
  responseInfo(CMCObjectIdentifiers.id_cmc_responseInfo),

  /** CMC Query pending */
  queryPending(CMCObjectIdentifiers.id_cmc_queryPending),

  /** CMC POP link random */
  popLinkRandom(CMCObjectIdentifiers.id_cmc_popLinkRandom),

  /** CMC POP link witness */
  popLinkWitness(CMCObjectIdentifiers.id_cmc_popLinkWitness),

  /** CMC POP link witness V2 */
  popLinkWitnessV2(CMCObjectIdentifiers.id_cmc_popLinkWitnessV2),

  /** CMC confirm certificate acceptance */
  confirmCertAcceptance(CMCObjectIdentifiers.id_cmc_confirmCertAcceptance),

  /** CMC status info V2 */
  statusInfoV2(CMCObjectIdentifiers.id_cmc_statusInfoV2),

  /** CMC trusted anchors */
  trustedAnchors(CMCObjectIdentifiers.id_cmc_trustedAnchors),

  /** CMC auth data */
  authData(CMCObjectIdentifiers.id_cmc_authData),

  /** CMC batch requests */
  batchRequests(CMCObjectIdentifiers.id_cmc_batchRequests),

  /** CMC batch responses */
  batchResponses(CMCObjectIdentifiers.id_cmc_batchResponses),

  /** CMC publish certificate */
  publishCert(CMCObjectIdentifiers.id_cmc_publishCert),

  /** CMC public certificate */
  modCertTemplate(CMCObjectIdentifiers.id_cmc_modCertTemplate),

  /** CMC control processed */
  controlProcessed(CMCObjectIdentifiers.id_cmc_controlProcessed),

  /** CMC identity proof V2 */
  identityProofV2(CMCObjectIdentifiers.id_cmc_identityProofV2);

  private ASN1ObjectIdentifier oid;

  /**
   * Return the Enum instance of the CMC Control object identifier matching a specified ASN OID
   *
   * @param oid ASN.1 OID
   * @return Enum instance if match found, or else null
   */
  public static CMCControlObjectID getControlObjectID(final String oid) {
    try {
      return getControlObjectID(new ASN1ObjectIdentifier(oid));
    }
    catch (Exception ex) {
      log.debug("Illegal Object Identifier: {}", ex.toString());
      return null;
    }
  }

  /**
   * Return the Enum instance of the CMC Control object identifier matching a specified ASN OID
   *
   * @param oid ASN.1 OID
   * @return Enum instance if match found, or else null
   */
  public static CMCControlObjectID getControlObjectID(final ASN1ObjectIdentifier oid) {
    return Arrays.stream(values())
        .filter(cmcControlObjectID -> cmcControlObjectID.getOid().equals(oid))
        .findFirst()
        .orElse(null);
  }

}
