/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_RECORD_RX_H
# define OSSL_QUIC_RECORD_RX_H

# include <openssl/ssl.h>
# include "internal/quic_wire_pkt.h"
# include "internal/quic_types.h"
# include "internal/quic_record_util.h"
# include "internal/quic_demux.h"

/*
 * QUIC Record Layer - RX
 * ======================
 */
typedef struct ossl_qrx_st OSSL_QRX;

typedef struct ossl_qrx_args_st {
    OSSL_LIB_CTX   *libctx;
    const char     *propq;

    /* Demux to receive datagrams from. */
    QUIC_DEMUX     *demux;

    /* Length of connection IDs used in short-header packets in bytes. */
    size_t          short_conn_id_len;

    /* Initial reference PN used for RX. */
    QUIC_PN         init_largest_pn[QUIC_PN_SPACE_NUM];
} OSSL_QRX_ARGS;

/* Instantiates a new QRX. */
OSSL_QRX *ossl_qrx_new(const OSSL_QRX_ARGS *args);

/*
 * Frees the QRX. All packets obtained using ossl_qrx_read_pkt must already
 * have been released by calling ossl_qrx_release_pkt.
 *
 * You do not need to call ossl_qrx_remove_dst_conn_id first; this function will
 * unregister the QRX from the demuxer for all registered destination connection
 * IDs (DCIDs) automatically.
 */
void ossl_qrx_free(OSSL_QRX *qrx);

/*
 * DCID Management
 * ===============
 */

/*
 * Adds a given DCID to the QRX. The QRX will register the DCID with the demuxer
 * so that incoming packets with that DCID are passed to the given QRX. Multiple
 * DCIDs may be associated with a QRX at any one time. You will need to add at
 * least one DCID after instantiating the QRX. A zero-length DCID is a valid
 * input to this function. This function fails if the DCID is already
 * registered.
 *
 * Returns 1 on success or 0 on error.
 */
int ossl_qrx_add_dst_conn_id(OSSL_QRX *qrx,
                             const QUIC_CONN_ID *dst_conn_id);

/*
 * Remove a DCID previously registered with ossl_qrx_add_dst_conn_id. The DCID
 * is unregistered from the demuxer. Fails if the DCID is not registered with
 * the demuxer.
 *
 * Returns 1 on success or 0 on error.
 */
int ossl_qrx_remove_dst_conn_id(OSSL_QRX *qrx,
                                const QUIC_CONN_ID *dst_conn_id);

/*
 * Secret Management
 * =================
 *
 * A QRX has several encryption levels (Initial, Handshake, 0-RTT, 1-RTT) and
 * two directions (RX, TX). At any given time, key material is managed for each
 * (EL, RX/TX) combination.
 *
 * Broadly, for a given (EL, RX/TX), the following state machine is applicable:
 *
 *   WAITING_FOR_KEYS --[Provide]--> HAVE_KEYS --[Discard]--> | DISCARDED |
 *         \-------------------------------------[Discard]--> |           |
 *
 * To transition the RX side of an EL from WAITING_FOR_KEYS to HAVE_KEYS, call
 * ossl_qrx_provide_secret (for the INITIAL EL, use of
 * ossl_qrl_provide_initial_secret is recommended).
 *
 * Once keys have been provisioned for an EL, you call
 * ossl_qrx_discard_enc_level to transition the EL to the DISCARDED state. You
 * can also call this function to transition directly to the DISCARDED state
 * even before any keys have been provisioned for that EL.
 *
 * The DISCARDED state is terminal for a given EL; you cannot provide a secret
 * again for that EL after reaching it.
 *
 * Incoming packets cannot be processed and decrypted if they target an EL
 * not in the HAVE_KEYS state. However, there is a distinction between
 * the WAITING_FOR_KEYS and DISCARDED states:
 *
 *   - In the WAITING_FOR_KEYS state, the QRX assumes keys for the given
 *     EL will eventually arrive. Therefore, if it receives any packet
 *     for an EL in this state, it buffers it and tries to process it
 *     again once the EL reaches HAVE_KEYS.
 *
 *   - In the DISCARDED state, the QRX assumes no keys for the given
 *     EL will ever arrive again. If it receives any packet for an EL
 *     in this state, it is simply discarded.
 *
 * If the user wishes to instantiate a new QRX to replace an old one for
 * whatever reason, for example to take over for an already established QUIC
 * connection, it is important that all ELs no longer being used (i.e., INITIAL,
 * 0-RTT, 1-RTT) are transitioned to the DISCARDED state. Otherwise, the QRX
 * will assume that keys for these ELs will arrive in future, and will buffer
 * any received packets for those ELs perpetually. This can be done by calling
 * ossl_qrx_discard_enc_level for all non-1-RTT ELs immediately after
 * instantiating the QRX.
 *
 * The INITIAL EL is not setup automatically when the QRX is instantiated. This
 * allows the caller to instead discard it immediately after instantiation of
 * the QRX if it is not needed, for example if the QRX is being instantiated to
 * take over handling of an existing connection which has already passed the
 * INITIAL phase. This avoids the unnecessary derivation of INITIAL keys where
 * they are not needed. In the ordinary case, ossl_qrx_provide_secret_initial
 * should be called immediately after instantiation.
 */

/*
 * Provides a secret to the QRX, which arises due to an encryption level change.
 * enc_level is a QUIC_ENC_LEVEL_* value. To initialise the INITIAL encryption
 * level, it is recommended to use ossl_qrl_provide_initial_secret instead.
 *
 * You should seek to call this function for a given EL before packets of that
 * EL arrive and are processed by the QRX. However, if packets have already
 * arrived for a given EL, the QRX will defer processing of them and perform
 * processing of them when this function is eventually called for the EL in
 * question.
 *
 * suite_id is a QRX_SUITE_* value which determines the AEAD function used for
 * the QRX.
 *
 * The secret passed is used directly to derive the "quic key", "quic iv" and
 * "quic hp" values.
 *
 * secret_len is the length of the secret buffer in bytes. The buffer must be
 * sized correctly to the chosen suite, else the function fails.
 *
 * This function can only be called once for a given EL. Subsequent calls fail,
 * as do calls made after a corresponding call to ossl_qrx_discard_enc_level for
 * that EL. The secret for a EL cannot be changed after it is set because QUIC
 * has no facility for introducing additional key material after an EL is setup.
 * QUIC key updates are managed automatically by the QRX and do not require user
 * intervention.
 *
 * md is for internal use and should be NULL.
 *
 * Returns 1 on success or 0 on failure.
 */
int ossl_qrx_provide_secret(OSSL_QRX              *qrx,
                            uint32_t               enc_level,
                            uint32_t               suite_id,
                            EVP_MD                *md,
                            const unsigned char   *secret,
                            size_t                 secret_len);

/*
 * Informs the QRX that it can now discard key material for a given EL. The QRX
 * will no longer be able to process incoming packets received at that
 * encryption level. This function is idempotent and succeeds if the EL has
 * already been discarded.
 *
 * Returns 1 on success and 0 on failure.
 */
int ossl_qrx_discard_enc_level(OSSL_QRX *qrx, uint32_t enc_level);

/*
 * Packet Reception
 * ================
 */

/* Information about a received packet. */
typedef struct ossl_qrx_pkt_st {
    /* Opaque handle to be passed to ossl_qrx_release_pkt. */
    void               *handle;

    /*
     * Points to a logical representation of the decoded QUIC packet header. The
     * data and len fields point to the decrypted QUIC payload (i.e., to a
     * sequence of zero or more (potentially malformed) frames to be decoded).
     */
    QUIC_PKT_HDR       *hdr;

    /*
     * Address the packet was received from. If this is not available for this
     * packet, this field is NULL (but this can only occur for manually injected
     * packets).
     */
    const BIO_ADDR     *peer;

    /*
     * Local address the packet was sent to. If this is not available for this
     * packet, this field is NULL.
     */
    const BIO_ADDR     *local;

    /*
     * This is the length of the datagram which contained this packet. Note that
     * the datagram may have contained other packets than this. The intended use
     * for this is so that the user can enforce minimum datagram sizes (e.g. for
     * datagrams containing INITIAL packets), as required by RFC 9000.
     */
    size_t              datagram_len;
} OSSL_QRX_PKT;

/*
 * Tries to read a new decrypted packet from the QRX.
 *
 * On success, all fields of *pkt are filled and 1 is returned.
 * Else, returns 0.
 *
 * The resources referenced by pkt->hdr, pkt->data and pkt->peer will remain
 * allocated at least until the user frees them by calling ossl_qrx_release_pkt,
 * which must be called once you are done with the packet.
 */
int ossl_qrx_read_pkt(OSSL_QRX *qrx, OSSL_QRX_PKT *pkt);

/*
 * Release the resources pointed to by an OSSL_QRX_PKT returned by
 * ossl_qrx_read_pkt. Pass the opaque value pkt->handle returned in the
 * structure.
 */
void ossl_qrx_release_pkt(OSSL_QRX *qrx, void *handle);

/*
 * Returns 1 if there are any already processed (i.e. decrypted) packets waiting
 * to be read from the QRX.
 */
int ossl_qrx_processed_read_pending(OSSL_QRX *qrx);

/*
 * Returns 1 if there arre any unprocessed (i.e. not yet decrypted) packets
 * waiting to be processed by the QRX. These may or may not result in
 * successfully decrypted packets once processed. This indicates whether
 * unprocessed data is buffered by the QRX, not whether any data is available in
 * a kernel socket buffer.
 */
int ossl_qrx_unprocessed_read_pending(OSSL_QRX *qrx);

/*
 * Returns the number of UDP payload bytes received from the network so far
 * since the last time this counter was cleared. If clear is 1, clears the
 * counter and returns the old value.
 *
 * The intended use of this is to allow callers to determine how much credit to
 * add to their anti-amplification budgets. This is reported separately instead
 * of in the OSSL_QRX_PKT structure so that a caller can apply
 * anti-amplification credit as soon as a datagram is received, before it has
 * necessarily read all processed packets contained within that datagram from
 * the QRX.
 */
uint64_t ossl_qrx_get_bytes_received(OSSL_QRX *qrx, int clear);

/*
 * Sets a callback which is called when a packet is received and being
 * validated before being queued in the read queue. This is called before packet
 * body decryption. pn_space is a QUIC_PN_SPACE_* value denoting which PN space
 * the PN belongs to.
 *
 * If this callback returns 1, processing continues normally.
 * If this callback returns 0, the packet is discarded.
 *
 * Other packets in the same datagram will still be processed where possible.
 *
 * The intended use for this function is to allow early validation of whether
 * a PN is a potential duplicate before spending CPU time decrypting the
 * packet payload.
 *
 * The callback is optional and can be unset by passing NULL for cb.
 * cb_arg is an opaque value passed to cb.
 */
typedef int (ossl_qrx_early_validation_cb)(QUIC_PN pn, int pn_space,
                                           void *arg);

int ossl_qrx_set_early_validation_cb(OSSL_QRX *qrx,
                                     ossl_qrx_early_validation_cb *cb,
                                     void *cb_arg);

/*
 * Key Update (RX)
 * ===============
 *
 * Key update on the RX side is a largely but not entirely automatic process.
 *
 * Key update is initially triggered by receiving a 1-RTT packet with a
 * different Key Phase value. This could be caused by an attacker in the network
 * flipping random bits, therefore such a key update is tentative until the
 * packet payload is successfully decrypted and authenticated by the AEAD with
 * the 'next' keys. These 'next' keys then become the 'current' keys and the
 * 'current' keys then become the 'previous' keys. The 'previous' keys must be
 * kept around temporarily as some packets may still be in flight in the network
 * encrypted with the old keys. If the old Key Phase value is X and the new Key
 * Phase Value is Y (where obviously X != Y), this creates an ambiguity as any
 * new packet received with a KP of X could either be an attempt to initiate yet
 * another key update right after the last one, or an old packet encrypted
 * before the key update.
 *
 * RFC 9001 provides some guidance on handling this issue:
 *
 *   Strategy 1:
 *      Three keys, disambiguation using packet numbers
 *
 *      "A recovered PN that is lower than any PN from the current KP uses the
 *       previous packet protection keys; a recovered PN that is higher than any
 *       PN from the current KP requires use of the next packet protection
 *       keys."
 *
 *   Strategy 2:
 *      Two keys and a timer
 *
 *      "Alternatively, endpoints can retain only two sets of packet protection
 *       neys, swapping previous keys for next after enough time has passed to
 *       allow for reordering in the network. In this case, the KP bit alone can
 *       be used to select keys."
 *
 * Strategy 2 is more efficient (we can keep fewer cipher contexts around) and
 * should cover all actually possible network conditions. It also allows a delay
 * after we make the 'next' keys our 'current' keys before we generate new
 * 'next' keys, which allows us to mitigate against malicious peers who try to
 * initiate an excessive number of key updates.
 *
 * We therefore model the following state machine:
 *
 *                          NORMAL  <----------\
 *                             |               |
 *                             |               |
 *                             v               |
 *                      UPDATE_CONFIRMED       |
 *                             |               |
 *                             |               |
 *                             v               |
 *                          COOLDOWN           |
 *                             |               |
 *                             |               |
 *                             \---------------|
 *
 * The RX starts in the NORMAL state. In the NORMAL state, the current expected
 * value of the Key Phase bit is recorded. When a flipped Key Phase bit is
 * detected, the RX attempts to decrypt and authenticate the received packet
 * with the 'next' keys rather than the 'current' keys. If (and only if) this
 * authentication is successful, we move to the UPDATE_CONFIRMED state. (An
 * attacker in the network could flip the Key Phase bit randomly, so it is
 * essential we do nothing until AEAD authentication is complete.)
 *
 * In the UPDATE_CONFIRMED state, we know a key update is occurring and record
 * that the new Key Phase bit value is the newly current value, but we still
 * keep the old keys around so that we can still process any packets which were
 * still in flight when the key update was initiated. In the UPDATE_CONFIRMED
 * state, a Key Phase bit value different to the current expected value is
 * treated not as the initiation of another key update, but a reference to our
 * old keys.
 *
 * Eventually we will be reasonably sure we are not going to receive any more
 * packets with the old keys. At this point, we can transition to the COOLDOWN
 * state. This transition occurs automatically after a certain amount of time;
 * RFC 9001 recommends it be the PTO interval, which relates to our RTT to the
 * peer. The duration also SHOULD NOT exceed three times the PTO to assist with
 * maintaining PFS.
 *
 * In the COOLDOWN phase, the old keys have been securely erased and only one
 * set of keys can be used: the current keys. If a packet is received with a Key
 * Phase bit value different to the current Key Phase Bit value, this is treated
 * as a request for a Key Update, but this request is ignored and the packet is
 * treated as malformed. We do this to allow mitigation against malicious peers
 * trying to initiate an excessive number of Key Updates. The timeout for the
 * transition from UPDATE_CONFIRMED to COOLDOWN is recommended as adequate for
 * this purpose in itself by the RFC, so the normal additional timeout value for
 * the transition from COOLDOWN to normal is zero (immediate transition).
 *
 * A summary of each state:
 *
 *                        Exp KP  Uses Keys KS0    KS1    If Non-Expected KP Bit
 *                        ------  --------- ------ -----  ----------------------
 *      NORMAL            0       Keyset 0  Gen 0  Gen 1  → UPDATE_CONFIRMED
 *      UPDATE_CONFIRMED  1       Keyset 1  Gen 0  Gen 1  Use Keyset 0
 *      COOLDOWN          1       Keyset 1  Erased Gen 1  Ignore Packet
 *
 *      NORMAL            1       Keyset 1  Gen 2  Gen 1  → UPDATE_CONFIRMED
 *      UPDATE_CONFIRMED  0       Keyset 0  Gen 2  Gen 1  Use Keyset 1
 *      COOLDOWN          0       Keyset 0  Gen 2  Erased Ignore Packet
 *
 * Note that the key material for the next key generation ("key epoch") is
 * always kept in the NORMAL state (necessary to avoid side-channel attacks).
 * This material is derived during the transition from COOLDOWN to NORMAL.
 *
 * Note that when a peer initiates a Key Update, we MUST also initiate a Key
 * Update as per the RFC. The caller is responsible for detecting this condition
 * and making the necessary calls to the TX side by detecting changes to the
 * return value of ossl_qrx_get_key_epoch().
 *
 */

/*
 * Return the current RX key epoch. This is initially zero and is incremented by
 * one for every Key Update successfully signalled by the peer.
 *
 * A necessary implication of this API is that the least significant bit of the
 * returned value corresponds to the currently expected Key Phase bit, though
 * callers are not anticipated to have any need of this information.
 *
 * It is not possible for the returned value to overflow, as a QUIC connection
 * cannot support more than 2**62 packet numbers, and a connection must be
 * terminated if this limit is reached.
 *
 * The caller should use this function to detect when the key epoch has changed
 * and use it to initiate a key update on the TX side.
 *
 * The value returned by this function increments specifically at the transition
 * from the NORMAL to the UPDATE_CONFIRMED state discussed above.
 */
uint64_t ossl_qrx_get_key_epoch(OSSL_QRX *qrx);

/*
 * The caller should call this after the UPDATE_CONFIRMED state is reached,
 * after a timeout to be determined by the caller.
 *
 * This transitions from the UPDATE_CONFIRMED state to the COOLDOWN state (if
 * still in the UPDATE_CONFIRMED state). If normal is 1, then transitions from
 * the COOLDOWN state to the NORMAL state. Both transitions can be performed at
 * once if desired.
 *
 * If in the normal state, or if in the COOLDOWN state and normal is 0, this is
 * a no-op and returns 1.
 *
 * It is essential that the caller call this within a few PTO intervals of a key
 * update occurring (as detected by the caller in a call to
 * ossl_qrx_key_get_key_epoch()), as otherwise the peer will not be able to
 * perform a Key Update ever again.
 */
int ossl_qrx_key_update_timeout(OSSL_QRX *qrx, int normal);


/*
 * Key Expiration
 * ==============
 */

/*
 * Returns the number of seemingly forged packets which have been received by
 * the QRX. If this value reaches the value returned by
 * ossl_qrx_get_max_epoch_forged_pkt_count(), all further received encrypted
 * packets will be discarded without processing; thus, callers should trigger a
 * key update on the TX side (which will cause the peer to trigger a key update
 * on our RX side) well before this occurs.
 */
uint64_t ossl_qrx_get_cur_epoch_forged_pkt_count(OSSL_QRX *qrx,
                                                 uint32_t enc_level);

/*
 * Returns the maximum number of forged packets which the record layer
 * will permit to be verified using the current set of RX keys.
 */
uint64_t ossl_qrx_get_max_epoch_forged_pkt_count(OSSL_QRX *qrx,
                                                 uint32_t enc_level);

#endif
