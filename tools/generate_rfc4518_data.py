#!/usr/bin/env python3
"""Generate RFC 4518 / RFC 3454 Unicode 3.2 stringprep tables for Zig.

The generated module is intentionally data-only.  It derives all mapping,
normalization, combining-class, composition, prohibited, and unassigned tables
from Python's bundled RFC 3454 `stringprep` module and Unicode 3.2 database.
"""

from __future__ import annotations

import stringprep
import unicodedata
from pathlib import Path


UCD = unicodedata.ucd_3_2_0
MAX_SCALAR = 0x10FFFF
OUT = Path("src/pki/rfc4518_data.zig")


def valid_scalar(cp: int) -> bool:
    return cp <= MAX_SCALAR and not (0xD800 <= cp <= 0xDFFF)


def chars_to_scalars(value: str) -> list[int]:
    return [ord(ch) for ch in value]


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
    return chars_to_scalars(stringprep.map_table_b2(chr(cp)))


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
    unassigned_values: list[int] = []
    prohibited_values: list[int] = []

    for cp in range(MAX_SCALAR + 1):
        if not valid_scalar(cp):
            continue
        mapped = rfc4518_map(cp)
        if mapped != [cp]:
            map_entries.append((cp, mapped))

        decomp = nfkd_mapping(cp)
        if decomp != [cp]:
            nfkd_entries.append((cp, decomp))

        ccc = UCD.combining(chr(cp))
        if ccc != 0:
            ccc_values.append((cp, ccc))

        if stringprep.in_table_a1(chr(cp)):
            unassigned_values.append(cp)
        if prohibited(cp):
            prohibited_values.append(cp)

    lines: list[str] = [
        "//! Generated by tools/generate_rfc4518_data.py from Python's RFC 3454",
        "//! stringprep module and Unicode 3.2.0 database. Do not edit by hand.",
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

    emit_ranges("unassigned", coalesce_ranges(unassigned_values), lines)
    emit_ranges("prohibited", coalesce_ranges(prohibited_values), lines)

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
