/*
 * FECTP over a C ABI — the sans-IO session layer.
 *
 * This turns payloads into frames and frames back into payloads. It does no
 * I/O: you read and write the socket, on your own thread, in your own idiom.
 * Nothing here blocks, owns a thread, or allocates memory you have to free
 * through anything but the matching *_free below.
 *
 * BSD 3-Clause. https://github.com/YounghyeonPark/fectp
 *
 * NOT AUDITED. This has not been reviewed by anyone who breaks protocols for a
 * living. Do not put it in front of an adversary yet.
 *
 * ---------------------------------------------------------------------------
 * The secret key
 *
 * There is no call that reads a private key out of an identity. That is
 * deliberate and not an oversight: bytes handed to a host language cannot be
 * wiped. A Python `bytes` and a Java `byte[]` are immortal, are copied by
 * their runtime, and may reach swap, and nothing this library does survives
 * the crossing. Keep the handle; do not keep the bytes.
 *
 * fectp_identity_from_secret() exists for restoring a key you already stored.
 * It wipes its own copy before returning. The copy you passed in is yours to
 * erase.
 *
 * ---------------------------------------------------------------------------
 * Buffers
 *
 * Every output goes to a buffer you supply, with a length you supply. A buffer
 * too small is FECTP_ERR_BUFFER and nothing is written — never a truncation.
 * A NULL pointer with a zero length means "no payload" and is accepted; a NULL
 * pointer with a non-zero length is FECTP_ERR_NULL.
 *
 * Calls that produce data return the number of bytes written, which is >= 0.
 * Anything negative is one of the FECTP_ERR_* codes.
 *
 * ---------------------------------------------------------------------------
 * Handles and threads
 *
 * A handle is yours and must be freed exactly once. Passing a freed handle, or
 * the same handle to two threads at once, is undefined — these carry no lock.
 * One session per thread, or take a lock yourself. Passing NULL to any *_free
 * does nothing, as free(NULL) does.
 *
 * fectp_initiator_read_response() and fectp_responder_write_response() CONSUME
 * their handle: pass a pointer to it, and they free it and set it to NULL
 * whether they succeed or fail. A handshake cannot be retried from a half-read
 * state, so there is nothing to keep. Calling again with the NULL they left
 * returns FECTP_ERR_NULL rather than freeing anything twice.
 */

#ifndef FECTP_H
#define FECTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The call succeeded. Calls reporting a length return a non-negative one. */
#define FECTP_OK 0
/* A pointer was NULL, or a handle had already been consumed. */
#define FECTP_ERR_NULL (-1)
/* An output buffer was too small. Nothing was written to it. */
#define FECTP_ERR_BUFFER (-2)
/* The protocol rejected the input: a malformed frame, a failed
 * authentication, a handshake step out of order. Discard the datagram; anyone
 * can send bytes to a socket, so this is ordinary and not a fault. */
#define FECTP_ERR_PROTOCOL (-3)
/* A panic was caught at the boundary. That is a bug in FECTP. The handle it
 * happened on should be treated as unusable. */
#define FECTP_ERR_PANIC (-4)
/* A length did not fit this platform's intptr_t. Nothing was read or written. */
#define FECTP_ERR_TOO_LARGE (-5)

/* Public and secret keys are both 32 bytes. */
#define FECTP_KEY_LEN 32

typedef struct fectp_identity fectp_identity;
typedef struct fectp_initiator fectp_initiator;
typedef struct fectp_responder fectp_responder;
typedef struct fectp_session fectp_session;

/* ----------------------------------------------------------------- identity */

/* Generates an identity from the OS randomness. NULL if it cannot. */
fectp_identity *fectp_identity_generate(void);

/* Rebuilds an identity from 32 stored secret bytes. NULL if `secret` is NULL. */
fectp_identity *fectp_identity_from_secret(const uint8_t *secret);

/* Writes the 32-byte public key to `out`. FECTP_OK, or FECTP_ERR_NULL. */
intptr_t fectp_identity_public(const fectp_identity *identity, uint8_t *out);

/* Frees an identity, wiping its secret. */
void fectp_identity_free(fectp_identity *identity);

/* ---------------------------------------------------------------- initiator */

/*
 * Begins a handshake with the peer holding `peer_public`.
 *
 * `session_id` names this session to that peer and is yours to choose; it must
 * not collide with another live session to the same address. `max_frame` is
 * the largest frame this side will accept.
 */
fectp_initiator *fectp_initiator_new(const fectp_identity *identity,
                                     const uint8_t *peer_public,
                                     uint32_t session_id,
                                     uint16_t max_frame);

/* Writes the opening frame, carrying `payload`, to `out`. Returns its length. */
intptr_t fectp_initiator_write_init(fectp_initiator *initiator,
                                    const uint8_t *payload, size_t payload_len,
                                    uint8_t *out, size_t out_len);

/*
 * Reads the peer's reply and produces a session.
 *
 * CONSUMES *initiator, setting it to NULL, whether it succeeds or fails. On
 * success *session receives a handle for fectp_session_free(), and the return
 * value is the length of any payload the peer sent, written to `out`.
 */
intptr_t fectp_initiator_read_response(fectp_initiator **initiator,
                                       const uint8_t *frame, size_t frame_len,
                                       uint8_t *out, size_t out_len,
                                       fectp_session **session);

/* Frees an initiator abandoned before the handshake finished. */
void fectp_initiator_free(fectp_initiator *initiator);

/* ---------------------------------------------------------------- responder */

/* Prepares to answer handshakes aimed at `identity`. */
fectp_responder *fectp_responder_new(const fectp_identity *identity,
                                     uint16_t max_frame);

/* Reads an opening frame, writing any payload it carried to `out`. */
intptr_t fectp_responder_read_init(fectp_responder *responder,
                                   const uint8_t *frame, size_t frame_len,
                                   uint8_t *out, size_t out_len);

/*
 * Writes the reply, carrying `payload`, and produces a session.
 *
 * CONSUMES *responder, as fectp_initiator_read_response() does.
 */
intptr_t fectp_responder_write_response(fectp_responder **responder,
                                        const uint8_t *payload, size_t payload_len,
                                        uint8_t *out, size_t out_len,
                                        fectp_session **session);

/* Frees a responder abandoned before the handshake finished. */
void fectp_responder_free(fectp_responder *responder);

/* ------------------------------------------------------------------ session */

/* Encrypts `payload` into a data frame at `out`. Returns the frame's length. */
intptr_t fectp_session_seal(fectp_session *session,
                            const uint8_t *payload, size_t payload_len,
                            uint8_t *out, size_t out_len);

/*
 * Decrypts `frame`, writing its payload to `out`. Returns the payload length.
 *
 * `frame` is copied before decryption, so your buffer is left as it was.
 * A frame that fails to authenticate is FECTP_ERR_PROTOCOL: discard it.
 */
intptr_t fectp_session_open(fectp_session *session,
                            const uint8_t *frame, size_t frame_len,
                            uint8_t *out, size_t out_len);

/* Frees a session. */
void fectp_session_free(fectp_session *session);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FECTP_H */
