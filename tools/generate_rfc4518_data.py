#!/usr/bin/env python3
"""Generate RFC 4518 / RFC 3454 Unicode 3.2 stringprep tables for Zig.

The generated module is intentionally data-only.  It derives stringprep
classification tables from Python's bundled RFC 3454 `stringprep` module and
Unicode 3.2 database, with B.3 fallback case mappings pinned to
tools/unicode/UnicodeData-3.2.0.txt instead of the host Python Unicode version.
RFC 4518 Appendix A combining marks are encoded as the literal normative
Appendix A ranges because RFC 4518 makes that table definitive for
implementation, including its intentional deltas from Unicode 3.2 categories.
"""

from __future__ import annotations

import stringprep
import unicodedata
from pathlib import Path


UCD = unicodedata.ucd_3_2_0
MAX_SCALAR = 0x10FFFF
OUT = Path("src/pki/rfc4518_data.zig")
UNICODE_DATA = Path(__file__).resolve().parent / "unicode" / "UnicodeData-3.2.0.txt"

# RFC 4518 Appendix A, "Combining Marks".  Appendix A is normative and says
# this list is definitive for implementations.  Do not replace it with a
# Unicode general-category query: Unicode 3.2's Mn/Mc/Me set differs by U+05BD
# and U+094E..U+094F.
RFC4518_COMBINING_MARK_RANGES = (
    (0x0300, 0x034F),
    (0x0360, 0x036F),
    (0x0483, 0x0486),
    (0x0488, 0x0489),
    (0x0591, 0x05A1),
    (0x05A3, 0x05B9),
    (0x05BB, 0x05BC),
    (0x05BF, 0x05BF),
    (0x05C1, 0x05C2),
    (0x05C4, 0x05C4),
    (0x064B, 0x0655),
    (0x0670, 0x0670),
    (0x06D6, 0x06DC),
    (0x06DE, 0x06E4),
    (0x06E7, 0x06E8),
    (0x06EA, 0x06ED),
    (0x0711, 0x0711),
    (0x0730, 0x074A),
    (0x07A6, 0x07B0),
    (0x0901, 0x0903),
    (0x093C, 0x093C),
    (0x093E, 0x094F),
    (0x0951, 0x0954),
    (0x0962, 0x0963),
    (0x0981, 0x0983),
    (0x09BC, 0x09BC),
    (0x09BE, 0x09C4),
    (0x09C7, 0x09C8),
    (0x09CB, 0x09CD),
    (0x09D7, 0x09D7),
    (0x09E2, 0x09E3),
    (0x0A02, 0x0A02),
    (0x0A3C, 0x0A3C),
    (0x0A3E, 0x0A42),
    (0x0A47, 0x0A48),
    (0x0A4B, 0x0A4D),
    (0x0A70, 0x0A71),
    (0x0A81, 0x0A83),
    (0x0ABC, 0x0ABC),
    (0x0ABE, 0x0AC5),
    (0x0AC7, 0x0AC9),
    (0x0ACB, 0x0ACD),
    (0x0B01, 0x0B03),
    (0x0B3C, 0x0B3C),
    (0x0B3E, 0x0B43),
    (0x0B47, 0x0B48),
    (0x0B4B, 0x0B4D),
    (0x0B56, 0x0B57),
    (0x0B82, 0x0B82),
    (0x0BBE, 0x0BC2),
    (0x0BC6, 0x0BC8),
    (0x0BCA, 0x0BCD),
    (0x0BD7, 0x0BD7),
    (0x0C01, 0x0C03),
    (0x0C3E, 0x0C44),
    (0x0C46, 0x0C48),
    (0x0C4A, 0x0C4D),
    (0x0C55, 0x0C56),
    (0x0C82, 0x0C83),
    (0x0CBE, 0x0CC4),
    (0x0CC6, 0x0CC8),
    (0x0CCA, 0x0CCD),
    (0x0CD5, 0x0CD6),
    (0x0D02, 0x0D03),
    (0x0D3E, 0x0D43),
    (0x0D46, 0x0D48),
    (0x0D4A, 0x0D4D),
    (0x0D57, 0x0D57),
    (0x0D82, 0x0D83),
    (0x0DCA, 0x0DCA),
    (0x0DCF, 0x0DD4),
    (0x0DD6, 0x0DD6),
    (0x0DD8, 0x0DDF),
    (0x0DF2, 0x0DF3),
    (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A),
    (0x0E47, 0x0E4E),
    (0x0EB1, 0x0EB1),
    (0x0EB4, 0x0EB9),
    (0x0EBB, 0x0EBC),
    (0x0EC8, 0x0ECD),
    (0x0F18, 0x0F19),
    (0x0F35, 0x0F35),
    (0x0F37, 0x0F37),
    (0x0F39, 0x0F39),
    (0x0F3E, 0x0F3F),
    (0x0F71, 0x0F84),
    (0x0F86, 0x0F87),
    (0x0F90, 0x0F97),
    (0x0F99, 0x0FBC),
    (0x0FC6, 0x0FC6),
    (0x102C, 0x1032),
    (0x1036, 0x1039),
    (0x1056, 0x1059),
    (0x1712, 0x1714),
    (0x1732, 0x1734),
    (0x1752, 0x1753),
    (0x1772, 0x1773),
    (0x17B4, 0x17D3),
    (0x180B, 0x180D),
    (0x18A9, 0x18A9),
    (0x20D0, 0x20EA),
    (0x302A, 0x302F),
    (0x3099, 0x309A),
    (0xFB1E, 0xFB1E),
    (0xFE00, 0xFE0F),
    (0xFE20, 0xFE23),
    (0x1D165, 0x1D169),
    (0x1D16D, 0x1D172),
    (0x1D17B, 0x1D182),
    (0x1D185, 0x1D18B),
    (0x1D1AA, 0x1D1AD),
)


def valid_scalar(cp: int) -> bool:
    return cp <= MAX_SCALAR and not (0xD800 <= cp <= 0xDFFF)


def chars_to_scalars(value: str) -> list[int]:
    return [ord(ch) for ch in value]


def scalars_to_chars(value: list[int]) -> str:
    return "".join(chr(cp) for cp in value)


def load_unicode_3_2_lowercase() -> dict[int, int]:
    lowercase: dict[int, int] = {}
    with UNICODE_DATA.open("r", encoding="ascii") as source:
        for line in source:
            fields = line.rstrip("\n").split(";")
            if len(fields) < 14 or not fields[13]:
                continue
            lowercase[int(fields[0], 16)] = int(fields[13], 16)
    return lowercase


LOWERCASE_3_2 = load_unicode_3_2_lowercase()


def coalesce_ranges(values: list[int]) -> list[tuple[int, int]]:
    values = sorted(set(values))
    ranges: list[tuple[int, int]] = []
    if not values:
        return ranges
    start = prev = values[0]
    for value in values[1:]:
        if value == prev + 1:
            prev = value
            continue
        ranges.append((start, prev))
        start = prev = value
    ranges.append((start, prev))
    return ranges


def expand_ranges(ranges: tuple[tuple[int, int], ...]) -> list[int]:
    return [cp for first, last in ranges for cp in range(first, last + 1)]


def coalesce_ccc(values: list[tuple[int, int]]) -> list[tuple[int, int, int]]:
    values.sort()
    ranges: list[tuple[int, int, int]] = []
    if not values:
        return ranges
    start, ccc = values[0]
    prev = start
    for cp, next_ccc in values[1:]:
        if cp == prev + 1 and next_ccc == ccc:
            prev = cp
            continue
        ranges.append((start, prev, ccc))
        start = prev = cp
        ccc = next_ccc
    ranges.append((start, prev, ccc))
    return ranges


def map_to_space(cp: int) -> bool:
    return (
        cp in (0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0085)
        or cp in (0x0020, 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000)
        or 0x2000 <= cp <= 0x200A
    )


def map_to_nothing(cp: int) -> bool:
    return (
        cp in (0x00AD, 0x034F, 0x1806, 0xFFFC, 0x200B)
        or 0x180B <= cp <= 0x180D
        or 0xFE00 <= cp <= 0xFE0F
        or 0x0000 <= cp <= 0x0008
        or 0x000E <= cp <= 0x001F
        or 0x007F <= cp <= 0x0084
        or 0x0086 <= cp <= 0x009F
        or cp in (0x06DD, 0x070F, 0x180E)
        or 0x200C <= cp <= 0x200F
        or 0x202A <= cp <= 0x202E
        or 0x2060 <= cp <= 0x2063
        or 0x206A <= cp <= 0x206F
        or cp == 0xFEFF
        or 0xFFF9 <= cp <= 0xFFFB
        or 0x1D173 <= cp <= 0x1D17A
        or cp == 0xE0001
        or 0xE0020 <= cp <= 0xE007F
    )


def rfc4518_map(cp: int) -> list[int]:
    if map_to_space(cp):
        return [0x20]
    if map_to_nothing(cp):
        return []
    ch = chr(cp)
    if stringprep.in_table_a1(ch):
        return [cp]
    return map_table_b2(cp)


def map_table_b3(cp: int) -> list[int]:
    exception = stringprep.b3_exceptions.get(cp)
    if exception is not None:
        return chars_to_scalars(exception)
    return [LOWERCASE_3_2.get(cp, cp)]


def map_table_b3_string(value: str) -> str:
    out: list[int] = []
    for ch in value:
        out.extend(map_table_b3(ord(ch)))
    return scalars_to_chars(out)


def map_table_b2(cp: int) -> list[int]:
    al = scalars_to_chars(map_table_b3(cp))
    b = UCD.normalize("NFKC", al)
    bl = map_table_b3_string(b)
    c = UCD.normalize("NFKC", bl)
    return chars_to_scalars(c if b != c else al)


def is_hangul_syllable(cp: int) -> bool:
    return 0xAC00 <= cp <= 0xD7A3


def nfkd_mapping(cp: int) -> list[int]:
    if is_hangul_syllable(cp):
        return [cp]
    return chars_to_scalars(UCD.normalize("NFKD", chr(cp)))


def canonical_compositions() -> list[tuple[int, int, int]]:
    pairs: list[tuple[int, int, int]] = []
    for cp in range(MAX_SCALAR + 1):
        if not valid_scalar(cp) or is_hangul_syllable(cp):
            continue
        decomp = UCD.decomposition(chr(cp))
        if not decomp or decomp.startswith("<"):
            continue
        parts = [int(part, 16) for part in decomp.split()]
        if len(parts) != 2:
            continue
        if UCD.normalize("NFC", "".join(chr(part) for part in parts)) == chr(cp):
            pairs.append((parts[0], parts[1], cp))
    return sorted(pairs)


def prohibited(cp: int) -> bool:
    ch = chr(cp)
    return (
        stringprep.in_table_c3(ch)
        or stringprep.in_table_c4(ch)
        or stringprep.in_table_c5(ch)
        or stringprep.in_table_c8(ch)
        or cp == 0xFFFD
    )


def emit_mapping(name: str, entries: list[tuple[int, list[int]]], out: list[str]) -> None:
    data: list[int] = []
    out.append(f"pub const {name} = [_]ScalarMapping{{")
    for cp, mapped in entries:
        offset = len(data)
        data.extend(mapped)
        out.append(f"    .{{ .scalar = 0x{cp:X}, .offset = {offset}, .len = {len(mapped)} }},")
    out.append("};")
    out.append("")
    out.append(f"pub const {name}_data = [_]u21{{")
    for scalar in data:
        out.append(f"    0x{scalar:X},")
    out.append("};")
    out.append("")


def emit_ranges(name: str, ranges: list[tuple[int, int]], out: list[str]) -> None:
    out.append(f"pub const {name} = [_]Range{{")
    for first, last in ranges:
        out.append(f"    .{{ .first = 0x{first:X}, .last = 0x{last:X} }},")
    out.append("};")
    out.append("")


def main() -> None:
    map_entries: list[tuple[int, list[int]]] = []
    nfkd_entries: list[tuple[int, list[int]]] = []
    ccc_values: list[tuple[int, int]] = []
    combining_mark_values = expand_ranges(RFC4518_COMBINING_MARK_RANGES)
    ucd_mark_values: list[int] = []
    unassigned_values: list[int] = []
    prohibited_values: list[int] = []

    for cp in range(MAX_SCALAR + 1):
        if not valid_scalar(cp):
            continue
        mapped = rfc4518_map(cp)
        if stringprep.in_table_a1(chr(cp)) and not map_to_space(cp) and not map_to_nothing(cp):
            assert mapped == [cp], (
                f"Unicode 3.2 unassigned U+{cp:04X} was mapped to "
                f"{[f'U+{value:04X}' for value in mapped]}"
            )
        if mapped != [cp]:
            map_entries.append((cp, mapped))

        decomp = nfkd_mapping(cp)
        if decomp != [cp]:
            nfkd_entries.append((cp, decomp))

        ccc = UCD.combining(chr(cp))
        if ccc != 0:
            ccc_values.append((cp, ccc))
        if UCD.category(chr(cp)) in ("Mn", "Mc", "Me"):
            ucd_mark_values.append(cp)

        if stringprep.in_table_a1(chr(cp)):
            unassigned_values.append(cp)
        if prohibited(cp):
            prohibited_values.append(cp)

    assert rfc4518_map(0x10A0) == [0x10A0]
    assert rfc4518_map(0x04C0) == [0x04C0]
    assert rfc4518_map(0x00DF) == [0x0073, 0x0073]
    rfc_marks = set(combining_mark_values)
    ucd_marks = set(ucd_mark_values)
    assert ucd_marks - rfc_marks == {0x05BD}
    assert rfc_marks - ucd_marks == {0x094E, 0x094F}
    assert 0x05BD not in rfc_marks
    assert 0x0301 in rfc_marks
    assert 0x093E in rfc_marks

    lines: list[str] = [
        "//! Generated by tools/generate_rfc4518_data.py from Python's RFC 3454",
        "//! stringprep module, tools/unicode/UnicodeData-3.2.0.txt, and",
        "//! the literal RFC 4518 Appendix A combining-mark ranges.",
        "//! Do not edit by hand.",
        "",
        "pub const ScalarMapping = struct { scalar: u21, offset: u32, len: u8 };",
        "pub const Range = struct { first: u21, last: u21 };",
        "pub const CccRange = struct { first: u21, last: u21, ccc: u8 };",
        "pub const Composition = struct { first: u21, second: u21, composite: u21 };",
        "",
    ]

    emit_mapping("map", map_entries, lines)
    emit_mapping("nfkd", nfkd_entries, lines)

    lines.append("pub const combining_classes = [_]CccRange{")
    for first, last, ccc in coalesce_ccc(ccc_values):
        lines.append(f"    .{{ .first = 0x{first:X}, .last = 0x{last:X}, .ccc = {ccc} }},")
    lines.append("};")
    lines.append("")

    lines.append("pub const compositions = [_]Composition{")
    for first, second, composite in canonical_compositions():
        lines.append(f"    .{{ .first = 0x{first:X}, .second = 0x{second:X}, .composite = 0x{composite:X} }},")
    lines.append("};")
    lines.append("")

    emit_ranges("combining_marks", coalesce_ranges(combining_mark_values), lines)
    emit_ranges("unassigned", coalesce_ranges(unassigned_values), lines)
    emit_ranges("prohibited", coalesce_ranges(prohibited_values), lines)

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
