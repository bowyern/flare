"""Unit tests for the QUIC variable-length integer codec.

The fixtures lock the wire format from RFC 9000 §16 Appendix A
(the official worked examples). Cross-validated against the
aioquic reference implementation by hand-decoding each fixture
under aioquic's ``pull_uint_var`` and confirming byte parity.
"""

from std.testing import assert_equal, assert_true
from std.memory import Span

from flare.quic import (
    VARINT_MAX,
    Varint,
    decode_varint,
    encode_varint,
    varint_encoded_length,
)


def _hex_bytes(*hex: Int) -> List[UInt8]:
    """Build a byte buffer from int-encoded hex pairs."""
    var out = List[UInt8]()
    for v in hex:
        out.append(UInt8(v))
    return out^


def test_rfc9000_appendix_a_1byte_form() raises:
    """RFC 9000 §A.1 — 37 encodes as 0x25 (1 byte)."""
    var enc = encode_varint(UInt64(37))
    assert_equal(len(enc), 1)
    assert_equal(Int(enc[0]), 0x25)
    var dec = decode_varint(Span[UInt8](enc))
    assert_equal(dec.value, UInt64(37))
    assert_equal(dec.consumed, 1)


def test_rfc9000_appendix_a_2byte_form() raises:
    """RFC 9000 §A.1 — 15293 encodes as 0x7b bd (2 bytes)."""
    var enc = encode_varint(UInt64(15293))
    assert_equal(len(enc), 2)
    assert_equal(Int(enc[0]), 0x7B)
    assert_equal(Int(enc[1]), 0xBD)
    var dec = decode_varint(Span[UInt8](enc))
    assert_equal(dec.value, UInt64(15293))
    assert_equal(dec.consumed, 2)


def test_rfc9000_appendix_a_4byte_form() raises:
    """RFC 9000 §A.1 — 494878333 encodes as 0x9d 7f 3e 7d (4 bytes)."""
    var enc = encode_varint(UInt64(494878333))
    assert_equal(len(enc), 4)
    assert_equal(Int(enc[0]), 0x9D)
    assert_equal(Int(enc[1]), 0x7F)
    assert_equal(Int(enc[2]), 0x3E)
    assert_equal(Int(enc[3]), 0x7D)
    var dec = decode_varint(Span[UInt8](enc))
    assert_equal(dec.value, UInt64(494878333))
    assert_equal(dec.consumed, 4)


def test_rfc9000_appendix_a_8byte_form() raises:
    """RFC 9000 §A.1 — 151288809941952652 encodes as
    0xc2 19 7c 5e ff 14 e8 8c (8 bytes)."""
    var enc = encode_varint(UInt64(151288809941952652))
    assert_equal(len(enc), 8)
    assert_equal(Int(enc[0]), 0xC2)
    assert_equal(Int(enc[1]), 0x19)
    assert_equal(Int(enc[2]), 0x7C)
    assert_equal(Int(enc[3]), 0x5E)
    assert_equal(Int(enc[4]), 0xFF)
    assert_equal(Int(enc[5]), 0x14)
    assert_equal(Int(enc[6]), 0xE8)
    assert_equal(Int(enc[7]), 0x8C)
    var dec = decode_varint(Span[UInt8](enc))
    assert_equal(dec.value, UInt64(151288809941952652))
    assert_equal(dec.consumed, 8)


def test_boundary_values() raises:
    """Length transitions at 64, 16384, 2^30 -- the encoder must
    pick the shortest form, and the decoder must accept all of
    them."""
    # 63 is the largest 1-byte value
    assert_equal(varint_encoded_length(UInt64(63)), 1)
    # 64 is the smallest 2-byte value
    assert_equal(varint_encoded_length(UInt64(64)), 2)
    # 16383 is the largest 2-byte value
    assert_equal(varint_encoded_length(UInt64(16383)), 2)
    # 16384 is the smallest 4-byte value
    assert_equal(varint_encoded_length(UInt64(16384)), 4)
    # (2^30 - 1) is the largest 4-byte value
    assert_equal(varint_encoded_length(UInt64((1 << 30) - 1)), 4)
    # (2^30) is the smallest 8-byte value
    assert_equal(varint_encoded_length(UInt64(1 << 30)), 8)
    # VARINT_MAX is the largest 8-byte value
    assert_equal(varint_encoded_length(UInt64(VARINT_MAX)), 8)


def test_zero_round_trips() raises:
    """Zero is the smallest legal value; it encodes as a single
    zero byte and round-trips cleanly."""
    var enc = encode_varint(UInt64(0))
    assert_equal(len(enc), 1)
    assert_equal(Int(enc[0]), 0x00)
    var dec = decode_varint(Span[UInt8](enc))
    assert_equal(dec.value, UInt64(0))
    assert_equal(dec.consumed, 1)


def test_encoder_rejects_overflow() raises:
    """Values above ``2^62 - 1`` cannot be encoded; the encoder
    must reject rather than silently truncate."""
    var raised = False
    try:
        _ = encode_varint(UInt64(VARINT_MAX) + UInt64(1))
    except _:
        raised = True
    assert_true(raised)


def test_decoder_rejects_empty_buffer() raises:
    """An empty input buffer cannot represent any varint."""
    var raised = False
    var empty = List[UInt8]()
    try:
        _ = decode_varint(Span[UInt8](empty))
    except _:
        raised = True
    assert_true(raised)


def test_decoder_rejects_truncated_input() raises:
    """A buffer whose first byte announces a longer form than the
    available bytes must be rejected (not parsed as the available
    prefix)."""
    # 0x80 announces a 4-byte form, but we supply only 2 bytes.
    var truncated = List[UInt8]()
    truncated.append(UInt8(0x80))
    truncated.append(UInt8(0x00))
    var raised = False
    try:
        _ = decode_varint(Span[UInt8](truncated))
    except _:
        raised = True
    assert_true(raised)


def test_round_trip_many_values() raises:
    """Spot-check round-trip parity at every order of magnitude."""
    var samples = List[UInt64]()
    samples.append(UInt64(0))
    samples.append(UInt64(1))
    samples.append(UInt64(63))
    samples.append(UInt64(64))
    samples.append(UInt64(100))
    samples.append(UInt64(16383))
    samples.append(UInt64(16384))
    samples.append(UInt64(65535))
    samples.append(UInt64(1 << 20))
    samples.append(UInt64((1 << 30) - 1))
    samples.append(UInt64(1 << 30))
    samples.append(UInt64(1 << 40))
    samples.append(UInt64(1 << 50))
    samples.append(UInt64(VARINT_MAX))
    for i in range(len(samples)):
        var v = samples[i]
        var enc = encode_varint(v)
        var dec = decode_varint(Span[UInt8](enc))
        assert_equal(dec.value, v)
        assert_equal(dec.consumed, len(enc))


def test_decoder_consumes_only_first_varint() raises:
    """A buffer that contains a varint followed by trailing bytes
    must yield the first varint's value plus a ``consumed`` count
    that lets the caller advance past it cleanly."""
    var buf = List[UInt8]()
    # First varint: 37 (1 byte: 0x25)
    buf.append(UInt8(0x25))
    # Trailing bytes that aren't part of the varint
    buf.append(UInt8(0xFF))
    buf.append(UInt8(0xFE))
    var dec = decode_varint(Span[UInt8](buf))
    assert_equal(dec.value, UInt64(37))
    assert_equal(dec.consumed, 1)


def main() raises:
    test_rfc9000_appendix_a_1byte_form()
    test_rfc9000_appendix_a_2byte_form()
    test_rfc9000_appendix_a_4byte_form()
    test_rfc9000_appendix_a_8byte_form()
    test_boundary_values()
    test_zero_round_trips()
    test_encoder_rejects_overflow()
    test_decoder_rejects_empty_buffer()
    test_decoder_rejects_truncated_input()
    test_round_trip_many_values()
    test_decoder_consumes_only_first_varint()
    print("test_varint: OK")
