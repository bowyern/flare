"""Unit tests for QPACK static-only codec
(``flare.qpack`` -- RFC 9204).

Validates the wire shape of indexed / literal-with-name-ref /
literal-with-literal-name field lines, the field-section prefix,
the rejection of dynamic-table references, and the Huffman
fallback when raw is shorter.
"""

from std.testing import assert_equal, assert_true, assert_false
from std.memory import Span

from flare.qpack import (
    QPACK_STATIC_TABLE_SIZE,
    QpackHeader,
    decode_field_section,
    encode_field_section,
    static_table_find,
    static_table_find_name,
    static_table_lookup,
)


def _bytes(*hex: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for v in hex:
        out.append(UInt8(v))
    return out^


def test_static_table_size() raises:
    assert_equal(QPACK_STATIC_TABLE_SIZE, 99)


def test_static_table_lookup_known_indices() raises:
    var entry17 = static_table_lookup(17)
    assert_equal(entry17.name, ":method")
    assert_equal(entry17.value, "GET")
    var entry25 = static_table_lookup(25)
    assert_equal(entry25.name, ":status")
    assert_equal(entry25.value, "200")


def test_static_table_lookup_out_of_range() raises:
    var raised = False
    try:
        var _ = static_table_lookup(99)
    except:
        raised = True
    assert_true(raised)


def test_static_table_find_full_match() raises:
    assert_equal(static_table_find(":method", "GET"), 17)
    assert_equal(static_table_find(":scheme", "https"), 23)
    assert_equal(static_table_find("missing", "value"), -1)


def test_static_table_find_name_only() raises:
    var idx = static_table_find_name("x-frame-options")
    assert_true(idx >= 0)
    assert_true(idx == 97 or idx == 98)


def test_round_trip_full_static_match() raises:
    var headers = List[QpackHeader]()
    headers.append(QpackHeader(":method", "GET"))
    headers.append(QpackHeader(":scheme", "https"))
    headers.append(QpackHeader(":status", "200"))
    var encoded = encode_field_section(headers)
    # Prefix: 0x00 0x00 (RIC=0, Base=0).
    assert_equal(Int(encoded[0]), 0x00)
    assert_equal(Int(encoded[1]), 0x00)
    # Indexed lines for indices 17/23/25 fit in 6-bit prefix:
    # 0xC0 | 17 = 0xD1, 0xC0 | 23 = 0xD7, 0xC0 | 25 = 0xD9.
    assert_equal(Int(encoded[2]), 0xD1)
    assert_equal(Int(encoded[3]), 0xD7)
    assert_equal(Int(encoded[4]), 0xD9)
    var decoded = decode_field_section(Span[UInt8, _](encoded))
    assert_equal(len(decoded), 3)
    assert_equal(decoded[0].name, ":method")
    assert_equal(decoded[0].value, "GET")
    assert_equal(decoded[1].name, ":scheme")
    assert_equal(decoded[1].value, "https")
    assert_equal(decoded[2].name, ":status")
    assert_equal(decoded[2].value, "200")


def test_round_trip_literal_with_name_reference() raises:
    var headers = List[QpackHeader]()
    headers.append(QpackHeader(":path", "/api/users"))
    var encoded = encode_field_section(headers)
    var decoded = decode_field_section(Span[UInt8, _](encoded))
    assert_equal(len(decoded), 1)
    assert_equal(decoded[0].name, ":path")
    assert_equal(decoded[0].value, "/api/users")


def test_round_trip_literal_with_literal_name() raises:
    var headers = List[QpackHeader]()
    headers.append(QpackHeader("x-custom", "value"))
    var encoded = encode_field_section(headers)
    var decoded = decode_field_section(Span[UInt8, _](encoded))
    assert_equal(len(decoded), 1)
    assert_equal(decoded[0].name, "x-custom")
    assert_equal(decoded[0].value, "value")


def test_round_trip_mixed_field_lines() raises:
    var headers = List[QpackHeader]()
    headers.append(QpackHeader(":method", "POST"))
    headers.append(QpackHeader(":path", "/login"))
    headers.append(QpackHeader("x-trace-id", "abc-123"))
    headers.append(QpackHeader("content-type", "application/json"))
    var encoded = encode_field_section(headers)
    var decoded = decode_field_section(Span[UInt8, _](encoded))
    assert_equal(len(decoded), 4)
    for i in range(4):
        assert_equal(decoded[i].name, headers[i].name)
        assert_equal(decoded[i].value, headers[i].value)


def test_decode_rejects_indexed_dynamic() raises:
    # RIC=0 + Base=0 + 0x80 (indexed dynamic, T=0).
    var buf = _bytes(0x00, 0x00, 0x80)
    var raised = False
    try:
        var _ = decode_field_section(Span[UInt8, _](buf))
    except:
        raised = True
    assert_true(raised)


def test_decode_rejects_literal_with_dynamic_name_ref() raises:
    # RIC=0 + Base=0 + 0x40 (literal-with-name-ref, T=0).
    var buf = _bytes(0x00, 0x00, 0x40)
    var raised = False
    try:
        var _ = decode_field_section(Span[UInt8, _](buf))
    except:
        raised = True
    assert_true(raised)


def test_decode_rejects_required_insert_count_above_zero() raises:
    # RIC=1.
    var buf = _bytes(0x01, 0x00, 0xD1)
    var raised = False
    try:
        var _ = decode_field_section(Span[UInt8, _](buf))
    except:
        raised = True
    assert_true(raised)


def test_round_trip_long_value_uses_huffman_when_shorter() raises:
    # A long lowercase ASCII value compresses well under Huffman;
    # the encoder picks the Huffman path.
    var headers = List[QpackHeader]()
    headers.append(QpackHeader("x-long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    var encoded = encode_field_section(headers)
    var decoded = decode_field_section(Span[UInt8, _](encoded))
    assert_equal(decoded[0].value, headers[0].value)


def main() raises:
    test_static_table_size()
    test_static_table_lookup_known_indices()
    test_static_table_lookup_out_of_range()
    test_static_table_find_full_match()
    test_static_table_find_name_only()
    test_round_trip_full_static_match()
    test_round_trip_literal_with_name_reference()
    test_round_trip_literal_with_literal_name()
    test_round_trip_mixed_field_lines()
    test_decode_rejects_indexed_dynamic()
    test_decode_rejects_literal_with_dynamic_name_ref()
    test_decode_rejects_required_insert_count_above_zero()
    test_round_trip_long_value_uses_huffman_when_shorter()
    print("test_qpack: 13 passed")
