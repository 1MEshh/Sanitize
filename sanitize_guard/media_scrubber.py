"""Pure-Python binary media metadata chunk parser and scrubber.

Provides zero-dependency binary parsing and stripping for:
- PNG chunks: tEXt, iTXt, zTXt, eXIf, tIME (with CRC32 integrity verification)
- JPEG segments: APP1 (EXIF / GPS / XMP), APP2 (ICC profile), COM (comments)
- GIF extension blocks: 0x21 0xFE comment sub-blocks

Guarantees binary preservation of image raster/entropy payload and color palettes.
"""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Tuple


@dataclass(frozen=True)
class MetadataChunkInfo:
    """Diagnostic details of a detected metadata chunk or marker."""
    media_format: str
    chunk_type: str
    offset: int
    size: int
    description: str


@dataclass(frozen=True)
class ScrubResult:
    """Outcome of an image sanitization operation."""
    file_path: str
    media_format: str
    original_size: int
    cleaned_size: int
    bytes_saved: int
    stripped_chunks: list[str]
    is_modified: bool
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "media_format": self.media_format,
            "original_size": self.original_size,
            "cleaned_size": self.cleaned_size,
            "bytes_saved": self.bytes_saved,
            "stripped_chunks": self.stripped_chunks,
            "is_modified": self.is_modified,
            "error": self.error,
        }


# PNG Constants
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
DEFAULT_PNG_STRIP = {b"tEXt", b"iTXt", b"zTXt", b"eXIf", b"tIME"}
ESSENTIAL_PNG_CHUNKS = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}

# JPEG Constants
JPEG_SOI = b"\xFF\xD8"
JPEG_EOI = b"\xFF\xD9"
JPEG_APP1 = 0xE1  # EXIF / GPS / XMP
JPEG_APP2 = 0xE2  # ICC Profile / Flashpix
JPEG_COM = 0xFE   # Text Comment
JPEG_SOS = 0xDA   # Start of Scan

# GIF Constants
GIF87A_SIGNATURE = b"GIF87a"
GIF89A_SIGNATURE = b"GIF89a"
GIF_TRAILER = 0x3B
GIF_EXTENSION_INTRODUCER = 0x21
GIF_COMMENT_LABEL = 0xFE
GIF_GRAPHIC_CONTROL_LABEL = 0xF9
GIF_APP_EXTENSION_LABEL = 0xFF
GIF_IMAGE_DESCRIPTOR = 0x2C


class MediaScrubber:
    """Binary parser and metadata scrubber for PNG, JPEG, and GIF formats."""

    @staticmethod
    def detect_format(data: bytes) -> Optional[str]:
        """Identifies media format from initial magic bytes."""
        if len(data) >= 8 and data[:8] == PNG_SIGNATURE:
            return "PNG"
        if len(data) >= 2 and data[:2] == JPEG_SOI:
            return "JPEG"
        if len(data) >= 6 and (data[:6] == GIF87A_SIGNATURE or data[:6] == GIF89A_SIGNATURE):
            return "GIF"
        return None

    # =========================================================================
    # PNG PARSER & SCRUBBER
    # =========================================================================

    @classmethod
    def _parse_png(
        cls,
        data: bytes,
        strip_chunks: set[bytes],
    ) -> Tuple[bytes, list[str], list[MetadataChunkInfo]]:
        """Parses PNG chunks, validates CRC32, and strips requested metadata."""
        if len(data) < 8 or data[:8] != PNG_SIGNATURE:
            raise ValueError("Invalid PNG signature")

        offset = 8
        data_len = len(data)
        out = bytearray(PNG_SIGNATURE)
        stripped: list[str] = []
        findings: list[MetadataChunkInfo] = []
        has_ihdr = False
        has_iend = False

        while offset < data_len:
            if offset + 8 > data_len:
                raise ValueError(f"Truncated PNG chunk header at offset {offset}")

            length = struct.unpack(">I", data[offset:offset + 4])[0]
            chunk_type = data[offset + 4:offset + 8]
            total_chunk_len = 12 + length  # 4 len + 4 type + length data + 4 crc

            if offset + total_chunk_len > data_len:
                raise ValueError(
                    f"Truncated PNG chunk data: type {chunk_type.decode('latin1', errors='replace')}, "
                    f"expected {length} bytes, file ends at {data_len}"
                )

            chunk_data = data[offset + 8:offset + 8 + length]
            stored_crc = struct.unpack(">I", data[offset + 8 + length:offset + total_chunk_len])[0]

            # Verify CRC32
            calculated_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
            if calculated_crc != stored_crc:
                raise ValueError(
                    f"CRC32 mismatch in chunk {chunk_type.decode('latin1', errors='replace')} "
                    f"at offset {offset}: stored 0x{stored_crc:08X}, calculated 0x{calculated_crc:08X}"
                )

            type_str = chunk_type.decode("latin1", errors="replace")

            if chunk_type == b"IHDR":
                has_ihdr = True
            elif chunk_type == b"IEND":
                has_iend = True

            # Decide whether to strip
            if chunk_type in strip_chunks and chunk_type not in ESSENTIAL_PNG_CHUNKS:
                stripped.append(type_str)
                findings.append(
                    MetadataChunkInfo(
                        media_format="PNG",
                        chunk_type=type_str,
                        offset=offset,
                        size=total_chunk_len,
                        description=f"PNG metadata chunk: {type_str} ({length} bytes payload)",
                    )
                )
            else:
                out.extend(data[offset:offset + total_chunk_len])

            offset += total_chunk_len

        if not has_ihdr:
            raise ValueError("Corrupt PNG: missing IHDR chunk")
        if not has_iend:
            raise ValueError("Corrupt PNG: missing IEND chunk")

        return bytes(out), stripped, findings

    # =========================================================================
    # JPEG PARSER & SCRUBBER
    # =========================================================================

    @classmethod
    def _parse_jpeg(
        cls,
        data: bytes,
        strip_markers: set[int],
    ) -> Tuple[bytes, list[str], list[MetadataChunkInfo]]:
        """Parses JPEG marker segments and strips EXIF (APP1), APP2, and COM."""
        if len(data) < 2 or data[:2] != JPEG_SOI:
            raise ValueError("Invalid JPEG SOI marker")

        offset = 2
        data_len = len(data)
        out = bytearray(JPEG_SOI)
        stripped: list[str] = []
        findings: list[MetadataChunkInfo] = []

        while offset < data_len:
            # Advance through fill 0xFF bytes
            if data[offset] != 0xFF:
                # Seek to next 0xFF
                next_ff = data.find(b"\xFF", offset)
                if next_ff == -1:
                    out.extend(data[offset:])
                    break
                out.extend(data[offset:next_ff])
                offset = next_ff

            while offset < data_len and data[offset] == 0xFF:
                offset += 1

            if offset >= data_len:
                break

            marker = data[offset]
            offset += 1

            # Standalone markers with no length
            if marker == 0xD8:  # SOI
                out.extend(b"\xFF\xD8")
                continue
            if marker == 0xD9:  # EOI
                out.extend(b"\xFF\xD9")
                break
            if 0xD0 <= marker <= 0xD7:  # RST0..RST7
                out.extend(bytes([0xFF, marker]))
                continue
            if marker == 0x00:  # Stuffed byte
                out.extend(b"\xFF\x00")
                continue

            # Marker segments with 2-byte big-endian length
            if offset + 2 > data_len:
                raise ValueError(f"Truncated JPEG segment length at offset {offset}")

            seg_len = struct.unpack(">H", data[offset:offset + 2])[0]
            if seg_len < 2:
                raise ValueError(f"Invalid JPEG segment length {seg_len} at offset {offset}")

            total_seg_len = seg_len  # Length field includes the 2 length bytes
            if offset + total_seg_len > data_len:
                raise ValueError(f"Truncated JPEG segment data for marker 0x{marker:02X}")

            marker_name = cls._jpeg_marker_name(marker)

            # Check if this marker should be stripped
            if marker in strip_markers:
                stripped.append(marker_name)
                findings.append(
                    MetadataChunkInfo(
                        media_format="JPEG",
                        chunk_type=marker_name,
                        offset=offset - 2,
                        size=total_seg_len + 2,
                        description=f"JPEG metadata marker: {marker_name} ({seg_len - 2} bytes payload)",
                    )
                )
                offset += total_seg_len
            else:
                out.extend(bytes([0xFF, marker]))
                out.extend(data[offset:offset + total_seg_len])
                offset += total_seg_len

                # If this was SOS (Start of Scan), entropy-coded scan data follows immediately
                if marker == JPEG_SOS:
                    # Scan until next non-stuffed marker
                    scan_start = offset
                    while offset < data_len:
                        marker_pos = data.find(b"\xFF", offset)
                        if marker_pos == -1 or marker_pos + 1 >= data_len:
                            out.extend(data[scan_start:])
                            offset = data_len
                            break

                        next_byte = data[marker_pos + 1]
                        if next_byte == 0x00 or (0xD0 <= next_byte <= 0xD7):
                            # Stuffed byte or restart marker inside scan data
                            offset = marker_pos + 2
                        else:
                            # Genuine marker terminating entropy scan
                            out.extend(data[scan_start:marker_pos])
                            offset = marker_pos
                            break

        # Ensure EOI is present
        if not out.endswith(JPEG_EOI):
            out.extend(JPEG_EOI)

        return bytes(out), stripped, findings

    @staticmethod
    def _jpeg_marker_name(marker: int) -> str:
        """Returns human-readable name for JPEG markers."""
        if marker == 0xE1:
            return "APP1 (EXIF/GPS/XMP)"
        if marker == 0xE2:
            return "APP2 (ICC Profile)"
        if marker == 0xFE:
            return "COM (Comment)"
        if 0xE0 <= marker <= 0xEF:
            return f"APP{marker - 0xE0}"
        return f"MARKER_0x{marker:02X}"

    # =========================================================================
    # GIF PARSER & SCRUBBER
    # =========================================================================

    @classmethod
    def _parse_gif(
        cls,
        data: bytes,
    ) -> Tuple[bytes, list[str], list[MetadataChunkInfo]]:
        """Parses GIF blocks and strips 0x21 0xFE Comment Extension blocks."""
        if len(data) < 6 or (data[:6] != GIF87A_SIGNATURE and data[:6] != GIF89A_SIGNATURE):
            raise ValueError("Invalid GIF header")

        out = bytearray(data[:6])
        offset = 6
        data_len = len(data)

        # Logical Screen Descriptor (7 bytes)
        if offset + 7 > data_len:
            raise ValueError("Truncated GIF Logical Screen Descriptor")

        packed = data[offset + 4]
        out.extend(data[offset:offset + 7])
        offset += 7

        # Global Color Table if flag bit 7 is set
        has_gct = bool(packed & 0x80)
        if has_gct:
            gct_size = 3 * (2 ** ((packed & 0x07) + 1))
            if offset + gct_size > data_len:
                raise ValueError("Truncated GIF Global Color Table")
            out.extend(data[offset:offset + gct_size])
            offset += gct_size

        stripped: list[str] = []
        findings: list[MetadataChunkInfo] = []

        # Process blocks
        while offset < data_len:
            block_type = data[offset]

            if block_type == GIF_TRAILER:  # 0x3B
                out.append(GIF_TRAILER)
                break

            elif block_type == GIF_EXTENSION_INTRODUCER:  # 0x21
                if offset + 2 > data_len:
                    raise ValueError("Truncated GIF extension block header")

                label = data[offset + 1]
                ext_start = offset
                offset += 2

                # Comment Extension (0xFE) -> STRIP
                if label == GIF_COMMENT_LABEL:
                    comment_bytes = bytearray()
                    while offset < data_len:
                        sub_len = data[offset]
                        offset += 1
                        if sub_len == 0:
                            break
                        if offset + sub_len > data_len:
                            raise ValueError("Truncated GIF comment sub-block")
                        comment_bytes.extend(data[offset:offset + sub_len])
                        offset += sub_len

                    comment_text = comment_bytes.decode("latin1", errors="replace").strip()
                    stripped.append("Comment Extension (0xFE)")
                    findings.append(
                        MetadataChunkInfo(
                            media_format="GIF",
                            chunk_type="Comment (0xFE)",
                            offset=ext_start,
                            size=offset - ext_start,
                            description=f"GIF comment block: '{comment_text[:40]}...'",
                        )
                    )
                else:
                    # Retain other extensions (e.g. Graphic Control 0xF9, Application 0xFF)
                    out.extend(data[ext_start:offset])
                    # Copy sub-blocks
                    while offset < data_len:
                        sub_len = data[offset]
                        out.append(sub_len)
                        offset += 1
                        if sub_len == 0:
                            break
                        if offset + sub_len > data_len:
                            raise ValueError("Truncated GIF extension sub-block")
                        out.extend(data[offset:offset + sub_len])
                        offset += sub_len

            elif block_type == GIF_IMAGE_DESCRIPTOR:  # 0x2C
                # Image Descriptor: 10 bytes (0x2C + 9 bytes)
                if offset + 10 > data_len:
                    raise ValueError("Truncated GIF Image Descriptor")

                img_packed = data[offset + 9]
                out.extend(data[offset:offset + 10])
                offset += 10

                # Local Color Table if bit 7 set
                has_lct = bool(img_packed & 0x80)
                if has_lct:
                    lct_size = 3 * (2 ** ((img_packed & 0x07) + 1))
                    if offset + lct_size > data_len:
                        raise ValueError("Truncated GIF Local Color Table")
                    out.extend(data[offset:offset + lct_size])
                    offset += lct_size

                # LZW minimum code size
                if offset >= data_len:
                    raise ValueError("Missing GIF LZW code size")
                out.append(data[offset])
                offset += 1

                # Image data sub-blocks
                while offset < data_len:
                    sub_len = data[offset]
                    out.append(sub_len)
                    offset += 1
                    if sub_len == 0:
                        break
                    if offset + sub_len > data_len:
                        raise ValueError("Truncated GIF raster sub-block")
                    out.extend(data[offset:offset + sub_len])
                    offset += sub_len

            else:
                # Unknown block byte, terminate or append safely
                out.append(block_type)
                offset += 1

        if not out.endswith(bytes([GIF_TRAILER])):
            out.append(GIF_TRAILER)

        return bytes(out), stripped, findings

    # =========================================================================
    # PUBLIC HIGH-LEVEL API
    # =========================================================================

    @classmethod
    def inspect_bytes(
        cls,
        data: bytes,
        format_hint: Optional[str] = None,
    ) -> Tuple[str, list[MetadataChunkInfo]]:
        """Analyzes binary image data and returns all detected metadata chunks."""
        fmt = (format_hint or cls.detect_format(data) or "").upper()
        if not fmt:
            raise ValueError("Unsupported or unknown image format")

        if fmt == "PNG":
            _, _, findings = cls._parse_png(data, DEFAULT_PNG_STRIP)
            return "PNG", findings
        elif fmt in ("JPEG", "JPG"):
            _, _, findings = cls._parse_jpeg(data, {JPEG_APP1, JPEG_APP2, JPEG_COM})
            return "JPEG", findings
        elif fmt == "GIF":
            _, _, findings = cls._parse_gif(data)
            return "GIF", findings
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    @classmethod
    def scrub_bytes(
        cls,
        data: bytes,
        format_hint: Optional[str] = None,
    ) -> Tuple[bytes, list[str], str]:
        """Scrubs metadata from image bytes in memory."""
        fmt = (format_hint or cls.detect_format(data) or "").upper()
        if not fmt:
            raise ValueError("Unsupported or unknown image format")

        if fmt == "PNG":
            cleaned, stripped, _ = cls._parse_png(data, DEFAULT_PNG_STRIP)
            return cleaned, stripped, "PNG"
        elif fmt in ("JPEG", "JPG"):
            cleaned, stripped, _ = cls._parse_jpeg(data, {JPEG_APP1, JPEG_APP2, JPEG_COM})
            return cleaned, stripped, "JPEG"
        elif fmt == "GIF":
            cleaned, stripped, _ = cls._parse_gif(data)
            return cleaned, stripped, "GIF"
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    @classmethod
    def inspect_file(cls, path: str | Path) -> Tuple[str, list[MetadataChunkInfo]]:
        """Inspects an image file on disk for metadata."""
        file_p = Path(path)
        data = file_p.read_bytes()
        return cls.inspect_bytes(data)

    @classmethod
    def scrub_file(
        cls,
        src_path: str | Path,
        dst_path: Optional[str | Path] = None,
        inplace: bool = False,
    ) -> ScrubResult:
        """Scrubs an image file on disk, supporting in-place or separate output."""
        src = Path(src_path)
        if not src.is_file():
            return ScrubResult(
                file_path=str(src),
                media_format="UNKNOWN",
                original_size=0,
                cleaned_size=0,
                bytes_saved=0,
                stripped_chunks=[],
                is_modified=False,
                error="File does not exist",
            )

        try:
            raw_data = src.read_bytes()
            original_size = len(raw_data)
            cleaned_data, stripped, fmt = cls.scrub_bytes(raw_data)
            cleaned_size = len(cleaned_data)
            bytes_saved = max(0, original_size - cleaned_size)
            is_modified = bool(stripped or cleaned_size != original_size)

            if is_modified:
                target = src if inplace else Path(dst_path or src)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(cleaned_data)

            return ScrubResult(
                file_path=str(src),
                media_format=fmt,
                original_size=original_size,
                cleaned_size=cleaned_size,
                bytes_saved=bytes_saved,
                stripped_chunks=stripped,
                is_modified=is_modified,
            )
        except Exception as e:
            return ScrubResult(
                file_path=str(src),
                media_format="ERROR",
                original_size=src.stat().st_size if src.exists() else 0,
                cleaned_size=0,
                bytes_saved=0,
                stripped_chunks=[],
                is_modified=False,
                error=str(e),
            )
