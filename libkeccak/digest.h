#ifndef LIBKECCAK_DIGEST_H
#define LIBKECCAK_DIGEST_H

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "spec.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Datastructure that describes the state of a hashing process
// The `char`-size of the output hashsum is calculated by `(.n + 7) / 8`
typedef struct libkeccak_state {
  int64_t S[25]; // The lanes (state/sponge)
  long r; // The bitrate
  long c; // The capacity
  long n; // The output size
  long b; // The state size
  long w; // The word size
  int64_t wmod; // The word mask
  long l; // ℓ, the binary logarithm of the word size
  long nr; // 12 + 2ℓ, the number of rounds
  size_t mptr; // Pointer for `M`
  size_t mlen; // Size of `M`
  char *M; // Left over water to fill the sponge with at next update
} libkeccak_state_t;

/**
 * Initialise a state according to hashing specifications
 *
 * @param   state  The state that should be initialised
 * @param   spec   The specifications for the state
 * @return         Zero on success, -1 on error
 */
int libkeccak_state_initialise(libkeccak_state_t* state, const libkeccak_spec_t* spec);

/**
 * Reset a state according to hashing specifications
 *
 * @param  state  The state that should be reset
 */
static inline void
libkeccak_state_reset(libkeccak_state_t* state)
{
  state->mptr = 0;
  memset(state->S, 0, sizeof(state->S));
}

/**
 * Release resources allocation for a state without wiping sensitive data
 *
 * @param  state  The state that should be destroyed
 */
static inline void
libkeccak_state_fast_destroy(libkeccak_state_t* state)
{
  if (state == NULL)
    return;
  free(state->M);
  state->M = NULL;
}

/**
 * Wipe data in the state's message wihout freeing any data
 *
 * @param  state  The state that should be wipe
 */
void libkeccak_state_wipe_message(volatile libkeccak_state_t* state);

/**
 * Wipe data in the state's sponge wihout freeing any data
 *
 * @param  state  The state that should be wipe
 */
void libkeccak_state_wipe_sponge(volatile libkeccak_state_t* state);

/**
 * Wipe sensitive data wihout freeing any data
 *
 * @param  state  The state that should be wipe
 */
void libkeccak_state_wipe(volatile libkeccak_state_t* state);

/**
 * Release resources allocation for a state and wipe sensitive data
 *
 * @param  state  The state that should be destroyed
 */
static inline void
libkeccak_state_destroy(volatile libkeccak_state_t* state)
{
  if (!state)
    return;
  libkeccak_state_wipe(state);
  free(state->M);
  state->M = NULL;
}

/**
 * Wrapper for `libkeccak_state_initialise` that also allocates the states
 *
 * @param   spec  The specifications for the state
 * @return        The state, `NULL` on error
 */
static inline libkeccak_state_t *
libkeccak_state_create(const libkeccak_spec_t* spec)
{
  libkeccak_state_t* state = (libkeccak_state_t*)malloc(sizeof(libkeccak_state_t));
  if (!state || libkeccak_state_initialise(state, spec))
    return (libkeccak_state_t*)(free(state), NULL);
  return state;
}

/**
 * Wrapper for `libkeccak_state_fast_destroy` that also frees the allocation of the state
 *
 * @param  state  The state that should be freed
 */
static inline void
libkeccak_state_fast_free(libkeccak_state_t* state)
{
  libkeccak_state_fast_destroy(state);
  free(state);
}

/**
 * Wrapper for `libkeccak_state_destroy` that also frees the allocation of the state
 *
 * @param  state  The state that should be freed
 */
static inline void
libkeccak_state_free(volatile libkeccak_state_t* state)
{
#ifdef __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif
  libkeccak_state_destroy(state);
  free((libkeccak_state_t *)state);
#ifdef __GNUC__
# pragma GCC diagnostic pop
#endif
}

/**
 * Make a copy of a state
 *
 * @param   dest  The slot for the duplicate, must not be initialised (memory leak otherwise)
 * @param   src   The state to duplicate
 * @return        Zero on success, -1 on error
 */
int libkeccak_state_copy(libkeccak_state_t* dest, const libkeccak_state_t* src);

/**
 * A wrapper for `libkeccak_state_copy` that also allocates the duplicate
 *
 * @param   src  The state to duplicate
 * @return       The duplicate, `NULL` on error
 */
static inline libkeccak_state_t *
libkeccak_state_duplicate(const libkeccak_state_t* src)
{
  libkeccak_state_t* dest = (libkeccak_state_t*)malloc(sizeof(libkeccak_state_t));
  if (!dest || libkeccak_state_copy(dest, src))
    return (libkeccak_state_t*)(libkeccak_state_free(dest), NULL);
  return dest;
}

/**
 * Calculates the allocation size required for the second argument
 * of `libkeccak_state_marshal` (`char*  data)`)
 *
 * @param   state  The state as it will be marshalled by a subsequent call to `libkeccak_state_marshal`
 * @return         The allocation size needed for the buffer to which the state will be marshalled
 */
static inline size_t
libkeccak_state_marshal_size(const libkeccak_state_t* state)
{
  return sizeof(libkeccak_state_t) - sizeof(char*) + state->mptr * sizeof(char);
}

/**
 * Marshal a `libkeccak_state_t` into a buffer
 *
 * @param   state  The state to marshal
 * @param   data   The output buffer
 * @return         The number of bytes stored to `data`
 */
size_t libkeccak_state_marshal(const libkeccak_state_t* state, char* data);

/**
 * Unmarshal a `libkeccak_state_t` from a buffer
 *
 * @param   state  The slot for the unmarshalled state, must not be initialised (memory leak otherwise)
 * @param   data   The input buffer
 * @return         The number of bytes read from `data`, 0 on error
 */
size_t libkeccak_state_unmarshal(libkeccak_state_t* state, const char* data);

/**
 * Gets the number of bytes the `libkeccak_state_t` stored
 * at the beginning of `data` occupies
 *
 * @param   data  The data buffer
 * @return        The byte size of the stored state
 */
size_t libkeccak_state_unmarshal_skip(const char* data);

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Absorb more of the message to the Keccak sponge
 * without wiping sensitive data when possible
 *
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
int libkeccak_fast_update(libkeccak_state_t* state, const char* msg, size_t msglen);

/**
 * Absorb more of the message to the Keccak sponge
 * and wipe sensitive data when possible
 *
 * @param   state   The hashing state
 * @param   msg     The partial message
 * @param   msglen  The length of the partial message
 * @return          Zero on success, -1 on error
 */
int libkeccak_update(libkeccak_state_t* state, const char* msg, size_t msglen);

/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * without wiping sensitive data when possible
 *
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
int libkeccak_fast_digest(libkeccak_state_t* state, const char* msg, size_t msglen,
                          size_t bits, const char* suffix, char* hashsum);

/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * and wipe sensitive data when possible
 *
 * @param   state    The hashing state
 * @param   msg      The rest of the message, may be `NULL`
 * @param   msglen   The length of the partial message
 * @param   bits     The number of bits at the end of the message not covered by `msglen`
 * @param   suffix   The suffix concatenate to the message, only '1':s and '0':s, and NUL-termination
 * @param   hashsum  Output parameter for the hashsum, may be `NULL`
 * @return           Zero on success, -1 on error
 */
int libkeccak_digest(libkeccak_state_t* state, const char* msg, size_t msglen,
                     size_t bits, const char* suffix, char* hashsum);

/**
 * Force some rounds of Keccak-f
 *
 * @param  state  The hashing state
 * @param  times  The number of rounds
 */
void libkeccak_simple_squeeze(register libkeccak_state_t* state, register long times);

/**
 * Squeeze as much as is needed to get a digest a number of times
 *
 * @param  state  The hashing state
 * @param  times  The number of digests
 */
void libkeccak_fast_squeeze(register libkeccak_state_t* state, register long times);

/**
 * Squeeze out another digest
 *
 * @param  state    The hashing state
 * @param  hashsum  Output parameter for the hashsum
 */
void libkeccak_squeeze(register libkeccak_state_t* state, register char* hashsum);

#endif
