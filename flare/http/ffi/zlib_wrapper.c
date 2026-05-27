/**
 * flare HTTP - minimal zlib wrapper for Mojo FFI.
 *
 * Exposes a single-call compression/decompression API so Mojo never needs to
 * read back z_stream fields through raw pointer arithmetic after an external
 * call -- Mojo's LLVM JIT may serve stale register values for stack slots that
 * were modified by a foreign call, leading to incorrect "have = 0" reads.
 *
 * All functions take pointer arguments as void* (mapped to Mojo Int) and
 * integer parameters as int (mapped to Mojo c_int / Int32).
 *
 * Mojo callers must keep the OwnedDLHandle for this library alive across every
 * call by passing it as a 'read' (borrowed) parameter.  Mojo's ASAP destruction
 * policy otherwise calls dlclose() immediately after get_function() returns --
 * before the retrieved function pointer is ever invoked -- unmapping the library
 * and crashing the JIT on both macOS ARM64 and Linux.
 *
 * Build: see build.sh
 */

#include <zlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Decompress (inflate) ──────────────────────────────────────────────────── */

/**
 * Decompress ``in_len`` bytes from ``in_buf`` into ``out_buf``.
 *
 * Handles both gzip and zlib-wrapped deflate automatically.  Raw deflate is
 * tried as a fallback when ``window_bits = 47`` initial decompression fails.
 *
 * @param in_buf      Pointer to the compressed input bytes.
 * @param in_len      Number of compressed input bytes.
 * @param out_buf     Pointer to the output buffer (pre-allocated by caller).
 * @param out_cap     Size of the output buffer in bytes.
 * @param window_bits zlib windowBits: 47 = auto gzip/zlib, 15 = zlib,
 *                    -15 = raw deflate.
 * @return Number of bytes written to ``out_buf`` on success; negative zlib
 *         error code on failure.
 */
int flare_decompress(const void *in_buf, int in_len,
                     void *out_buf, int out_cap,
                     int window_bits) {
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));
    strm.next_in  = (Bytef *)in_buf;
    strm.avail_in = (uInt)in_len;

    int rc = inflateInit2(&strm, window_bits);
    if (rc != Z_OK) return rc;

    strm.next_out  = (Bytef *)out_buf;
    strm.avail_out = (uInt)out_cap;

    rc = inflate(&strm, Z_SYNC_FLUSH);
    int written = out_cap - (int)strm.avail_out;
    inflateEnd(&strm);

    if (rc == Z_STREAM_END || rc == Z_OK || rc == Z_BUF_ERROR) {
        return written;
    }
    return rc;  /* negative error code */
}

/**
 * Decompress a deflate-encoded buffer, trying zlib-wrapped first then raw.
 *
 * Matches browser behaviour for the ambiguous HTTP ``deflate`` encoding.
 *
 * @param in_buf   Pointer to the compressed input bytes.
 * @param in_len   Number of compressed input bytes.
 * @param out_buf  Pointer to the output buffer (pre-allocated by caller).
 * @param out_cap  Size of the output buffer in bytes.
 * @return Number of bytes written to ``out_buf`` on success; negative on failure.
 */
int flare_decompress_deflate(const void *in_buf, int in_len,
                              void *out_buf, int out_cap) {
    /* Try zlib-wrapped first (windowBits = 15) */
    int rc = flare_decompress(in_buf, in_len, out_buf, out_cap, 15);
    if (rc >= 0) return rc;

    /* Fall back to raw deflate (windowBits = -15) */
    return flare_decompress(in_buf, in_len, out_buf, out_cap, -15);
}

/* ── Compress (deflate) ────────────────────────────────────────────────────── */

/**
 * Compress ``in_len`` bytes from ``in_buf`` into a gzip container.
 *
 * @param in_buf   Pointer to the plaintext input bytes.
 * @param in_len   Number of plaintext input bytes.
 * @param out_buf  Pointer to the output buffer (pre-allocated by caller).
 * @param out_cap  Size of the output buffer in bytes.
 * @param level    Compression level (1–9; 0 = no compression; -1 = default).
 * @return Number of bytes written to ``out_buf`` on success; negative on failure.
 */
int flare_compress_gzip(const void *in_buf, int in_len,
                        void *out_buf, int out_cap,
                        int level) {
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));

    /* windowBits = 15 | 16 = gzip container; method = Z_DEFLATED */
    int rc = deflateInit2(&strm, level, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) return rc;

    strm.next_in   = (Bytef *)in_buf;
    strm.avail_in  = (uInt)in_len;
    strm.next_out  = (Bytef *)out_buf;
    strm.avail_out = (uInt)out_cap;

    rc = deflate(&strm, Z_FINISH);
    int written = out_cap - (int)strm.avail_out;
    deflateEnd(&strm);

    if (rc == Z_STREAM_END) return written;
    if (rc == Z_OK || rc == Z_BUF_ERROR) return written;  /* partial: buf_error */
    return rc;  /* negative error code */
}

/**
 * Compress ``in_len`` bytes from ``in_buf`` as a *raw* deflate stream
 * (no zlib or gzip header).  Used by RFC 7692 ``permessage-deflate``:
 * each WebSocket message is encoded as a raw deflate block, the
 * trailing 0x00 0x00 0xff 0xff sync marker is stripped by the
 * caller, and the receiving side restores the marker before
 * inflating.
 *
 * Always uses ``Z_SYNC_FLUSH`` so the output ends with the empty
 * deflate block (0x00 0x00 0xff 0xff).  Callers MUST drop those 4
 * bytes per RFC 7692 §7.2.1.
 *
 * @param in_buf   Pointer to the plaintext input bytes.
 * @param in_len   Number of plaintext input bytes.
 * @param out_buf  Pointer to the output buffer (pre-allocated).
 * @param out_cap  Size of the output buffer in bytes.
 * @param level    Compression level (1-9; 0 = no compression; -1 = default).
 * @return Number of bytes written on success; negative zlib error otherwise.
 */
int flare_compress_raw_deflate(const void *in_buf, int in_len,
                               void *out_buf, int out_cap,
                               int level) {
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));

    /* windowBits = -15 -> raw deflate (no zlib/gzip wrapper). */
    int rc = deflateInit2(&strm, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) return rc;

    strm.next_in   = (Bytef *)in_buf;
    strm.avail_in  = (uInt)in_len;
    strm.next_out  = (Bytef *)out_buf;
    strm.avail_out = (uInt)out_cap;

    /* Z_SYNC_FLUSH ensures the output ends with 0x00 0x00 0xff 0xff
       so the caller can strip the marker per RFC 7692 §7.2.1. */
    rc = deflate(&strm, Z_SYNC_FLUSH);
    int written = out_cap - (int)strm.avail_out;
    deflateEnd(&strm);

    if (rc == Z_OK || rc == Z_STREAM_END || rc == Z_BUF_ERROR) {
        return written;
    }
    return rc;
}

/**
 * Return the size of z_stream in bytes (for diagnostics).
 */
int flare_zstream_size(void) {
    return (int)sizeof(z_stream);
}

/* ── permessage-deflate persistent contexts (RFC 7692 §7.1) ──────────────── */
/*
 * The one-shot ``flare_compress_raw_deflate`` / ``flare_decompress`` helpers
 * above re-initialise the LZ77 window on every call, which corresponds to
 * the ``no_context_takeover`` mode of permessage-deflate (RFC 7692 §7.1.1.1
 * and §7.1.1.2). The functions below provide the inverse: a heap-allocated
 * ``z_stream`` that lives across multiple ``deflate``/``inflate`` calls so
 * the LZ77 sliding window carries between WebSocket messages.
 *
 * The handle is opaque from the Mojo side -- it is a ``void*`` cast to
 * ``intptr_t`` and passed back through every chunk + free call. The
 * caller is responsible for matching every ``_new`` with exactly one
 * ``_free`` so the wrapping ``deflateEnd`` / ``inflateEnd`` and the
 * heap free both run. Leaking a handle leaks the LZ77 dictionary plus
 * the zlib internal buffers (~256 KiB per stream at default settings).
 *
 * Concurrency: each handle is single-threaded. Calling
 * ``_compress_chunk`` on the same handle from two threads is undefined
 * behaviour (matches zlib's own contract). The WebSocket adapter
 * serialises sends and receives per connection, so this constraint is
 * cheap to honour.
 */

/**
 * Allocate a persistent deflate context for permessage-deflate.
 *
 * @param level        zlib compression level (1-9; -1 = default).
 * @param window_bits  Negative for raw deflate (no zlib/gzip wrapper);
 *                     RFC 7692 §7.1.2.1 negotiates a value in
 *                     [-15, -8] via ``server_max_window_bits`` /
 *                     ``client_max_window_bits``. Default -15 = 32 KiB
 *                     sliding window.
 * @return Non-zero opaque handle on success; 0 on allocation failure;
 *         negative zlib error code if ``deflateInit2`` rejects the
 *         parameters.
 */
intptr_t flare_pmd_compressor_new(int level, int window_bits) {
    z_stream *strm = (z_stream *)calloc(1, sizeof(z_stream));
    if (strm == NULL) return 0;
    int rc = deflateInit2(strm, level, Z_DEFLATED, window_bits, 8,
                          Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) {
        free(strm);
        return (intptr_t)rc;  /* negative zlib code; caller distinguishes
                                  by checking against the negative range */
    }
    return (intptr_t)strm;
}

/**
 * Compress one WebSocket message fragment with context-takeover.
 *
 * Uses ``Z_SYNC_FLUSH`` so the output ends with the empty deflate
 * block ``0x00 0x00 0xff 0xff``; callers strip those 4 bytes per
 * RFC 7692 §7.2.1 before sending the frame on the wire.
 *
 * The handle MUST have come from :func:`flare_pmd_compressor_new`;
 * passing any other pointer is undefined behaviour. The function does
 * not validate the handle because the FFI surface is private to the
 * ``flare.ws.permessage_deflate`` Mojo module.
 *
 * @param handle  Compressor handle from ``flare_pmd_compressor_new``.
 * @param in_buf  Plaintext bytes.
 * @param in_len  Length of ``in_buf``.
 * @param out_buf Pre-allocated output buffer.
 * @param out_cap Capacity of ``out_buf``.
 * @return Bytes written to ``out_buf`` on success; negative zlib error
 *         otherwise. A return of 0 is legal and means the message
 *         compressed to the empty sync marker only -- the marker
 *         strip leaves a zero-byte payload (``Z_SYNC_FLUSH`` on an
 *         already-flushed empty input).
 */
int flare_pmd_compress_chunk(intptr_t handle, const void *in_buf, int in_len,
                             void *out_buf, int out_cap) {
    z_stream *strm = (z_stream *)handle;
    if (strm == NULL) return Z_STREAM_ERROR;
    strm->next_in   = (Bytef *)in_buf;
    strm->avail_in  = (uInt)in_len;
    strm->next_out  = (Bytef *)out_buf;
    strm->avail_out = (uInt)out_cap;
    int rc = deflate(strm, Z_SYNC_FLUSH);
    int written = out_cap - (int)strm->avail_out;
    if (rc == Z_OK || rc == Z_BUF_ERROR) return written;
    return rc;
}

/**
 * Release a persistent deflate context. Must be called exactly once
 * per :func:`flare_pmd_compressor_new` to avoid leaking ~256 KiB of
 * zlib internal state.
 */
void flare_pmd_compressor_free(intptr_t handle) {
    z_stream *strm = (z_stream *)handle;
    if (strm == NULL) return;
    deflateEnd(strm);
    free(strm);
}

/**
 * Allocate a persistent inflate context for permessage-deflate.
 *
 * Parameters mirror :func:`flare_pmd_compressor_new`. Returns a
 * non-zero handle on success, 0 on alloc failure, or a negative zlib
 * code on ``inflateInit2`` failure.
 */
intptr_t flare_pmd_decompressor_new(int window_bits) {
    z_stream *strm = (z_stream *)calloc(1, sizeof(z_stream));
    if (strm == NULL) return 0;
    int rc = inflateInit2(strm, window_bits);
    if (rc != Z_OK) {
        free(strm);
        return (intptr_t)rc;
    }
    return (intptr_t)strm;
}

/**
 * Decompress one WebSocket message fragment with context-takeover.
 *
 * RFC 7692 §7.2.2 requires the receiver to append the deflate
 * sync marker (``0x00 0x00 0xff 0xff``) before inflating, since the
 * sender stripped it on the way out. The caller is responsible for
 * doing that prepend; this function inflates whatever bytes it gets.
 *
 * @return Bytes written to ``out_buf`` on success; negative zlib
 *         error otherwise. A return of 0 is legal and means the
 *         marker-padded payload decoded to no bytes (rare but valid).
 */
int flare_pmd_decompress_chunk(intptr_t handle, const void *in_buf, int in_len,
                               void *out_buf, int out_cap) {
    z_stream *strm = (z_stream *)handle;
    if (strm == NULL) return Z_STREAM_ERROR;
    strm->next_in   = (Bytef *)in_buf;
    strm->avail_in  = (uInt)in_len;
    strm->next_out  = (Bytef *)out_buf;
    strm->avail_out = (uInt)out_cap;
    int rc = inflate(strm, Z_SYNC_FLUSH);
    int written = out_cap - (int)strm->avail_out;
    if (rc == Z_OK || rc == Z_BUF_ERROR) return written;
    if (rc == Z_STREAM_END) return written;
    return rc;
}

/**
 * Release a persistent inflate context. Mirrors
 * :func:`flare_pmd_compressor_free`.
 */
void flare_pmd_decompressor_free(intptr_t handle) {
    z_stream *strm = (z_stream *)handle;
    if (strm == NULL) return;
    inflateEnd(strm);
    free(strm);
}
