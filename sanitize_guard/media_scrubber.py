"""Pure-Python binary media metadata chunk parser and scrubber.

Provides zero-dependency binary parsing and stripping for:
- PNG chunks: tEXt, iTXt, zTXt, eXIf, tIME (with CRC32 integrity verification)
- JPEG segments: APP1 (EXIF / GPS / XMP), APP2 (ICC profile), COM (comments)
- GIF extension blocks: 0x21 0xFE comment sub-blocks
- WebP chunks: EXIF and XMP chunks inside RIFF containers with VP8X flag updates
- MP3 audio streams: ID3v2 (synchsafe integer size) and ID3v1 metadata tags
- WAV audio containers: LIST/INFO metadata chunks and embedded ID3 tags

Guarantees binary preservation of audio streams, image rasters, and color palettes.
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
    """Outcome of an image or audio sanitization operation."""
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


# File Format Extensions
SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".wav"}

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

# WebP & RIFF Constants
RIFF_MAGIC = b"RIFF"
WEBP_MAGIC = b"WEBP"
WAVE_MAGIC = b"WAVE"
DEFAULT_WEBP_STRIP = {b"EXIF", b"XMP "}

# MP3 & ID3 Constants
ID3_MAGIC = b"ID3"


class MediaScrubber:
    """Binary parser and metadata scrubber for PNG, JPEG, GIF, WebP, MP3, and WAV formats."""

    SUPPORTED_EXTENSIONS = SUPPORTED_EXTENSIONS

    @staticmethod
    def detect_format(data: bytes) -> Optional[str]:
        """Identifies media format from initial magic bytes."""
        if len(data) >= 8 and data[:8] == PNG_SIGNATURE:
            return "PNG"
        if len(data) >= 2 and data[:2] == JPEG_SOI:
            return "JPEG"
        if len(data) >= 6 and (data[:6] == GIF87A_SIGNATURE or data[:6] == GIF89A_SIGNATURE):
            return "GIF"
        if len(data) >= 12 and data[:4] == RIFF_MAGIC:
            sub_type = data[8:12]
            if sub_type == WEBP_MAGIC:
                return "WEBP"
            if sub_type == WAVE_MAGIC:
                return "WAV"
        if len(data) >= 3 and data[:3] == ID3_MAGIC:
            return "MP3"
        if len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
            return "MP3"
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

            total_seg_len = seg_len
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

                if marker == JPEG_SOS:
                    scan_start = offset
                    while offset < data_len:
                        marker_pos = data.find(b"\xFF", offset)
                        if marker_pos == -1 or marker_pos + 1 >= data_len:
                            out.extend(data[scan_start:])
                            offset = data_len
                            break

                        next_byte = data[marker_pos + 1]
                        if next_byte == 0x00 or (0xD0 <= next_byte <= 0xD7):
                            offset = marker_pos + 2
                        else:
                            out.extend(data[scan_start:marker_pos])
                            offset = marker_pos
                            break

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
                    out.extend(data[ext_start:offset])
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
                if offset + 10 > data_len:
                    raise ValueError("Truncated GIF Image Descriptor")

                img_packed = data[offset + 9]
                out.extend(data[offset:offset + 10])
                offset += 10

                has_lct = bool(img_packed & 0x80)
                if has_lct:
                    lct_size = 3 * (2 ** ((img_packed & 0x07) + 1))
                    if offset + lct_size > data_len:
                        raise ValueError("Truncated GIF Local Color Table")
                    out.extend(data[offset:offset + lct_size])
                    offset += lct_size

                if offset >= data_len:
                    raise ValueError("Missing GIF LZW code size")
                out.append(data[offset])
                offset += 1

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
                out.append(block_type)
                offset += 1

        if not out.endswith(bytes([GIF_TRAILER])):
            out.append(GIF_TRAILER)

        return bytes(out), stripped, findings

    # =========================================================================
    # WEBP PARSER & SCRUBBER (RIFF Container)
    # =========================================================================

    @classmethod
    def _parse_webp(
        cls,
        data: bytes,
        strip_chunks: set[bytes] = DEFAULT_WEBP_STRIP,
    ) -> Tuple[bytes, list[str], list[MetadataChunkInfo]]:
        """Parses RIFF/WEBP FourCC chunks, strips EXIF and XMP, and updates VP8X flags."""
        if len(data) < 12 or data[:4] != RIFF_MAGIC or data[8:12] != WEBP_MAGIC:
            raise ValueError("Invalid WebP/RIFF header")

        data_len = len(data)
        out = bytearray(data[:12])  # 4 bytes RIFF, 4 bytes size, 4 bytes WEBP
        offset = 12
        stripped: list[str] = []
        findings: list[MetadataChunkInfo] = []

        while offset < data_len:
            if offset + 8 > data_len:
                raise ValueError(f"Truncated WebP chunk header at offset {offset}")

            fourcc = data[offset:offset + 4]
            chunk_len = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            pad = chunk_len % 2
            total_len = 8 + chunk_len + pad

            if offset + 8 + chunk_len > data_len:
                raise ValueError(f"Truncated WebP chunk {fourcc.decode('latin1', errors='replace')} data")

            fourcc_str = fourcc.decode("latin1", errors="replace")

            if fourcc in strip_chunks:
                stripped.append(fourcc_str.strip())
                findings.append(
                    MetadataChunkInfo(
                        media_format="WEBP",
                        chunk_type=fourcc_str.strip(),
                        offset=offset,
                        size=total_len,
                        description=f"WebP metadata chunk: {fourcc_str.strip()} ({chunk_len} bytes payload)",
                    )
                )
            elif fourcc == b"VP8X":
                # Extended header: clear EXIF (0x08) and XMP (0x04) flag bits in byte 0 of payload
                chunk_payload = bytearray(data[offset + 8:offset + 8 + chunk_len])
                if len(chunk_payload) >= 1:
                    chunk_payload[0] &= ~(0x08 | 0x04)

                out.extend(b"VP8X")
                out.extend(struct.pack("<I", len(chunk_payload)))
                out.extend(chunk_payload)
                if pad:
                    out.append(0)
            else:
                out.extend(data[offset:offset + total_len])

            offset += total_len

        # Recalculate RIFF size header
        out[4:8] = struct.pack("<I", len(out) - 8)
        return bytes(out), stripped, findings

    # =========================================================================
    # MP3 PARSER & SCRUBBER (ID3v2 and ID3v1 Tags)
    # =========================================================================

    @classmethod
    def _parse_mp3(
        cls,
        data: bytes,
    ) -> Tuple[bytes, list[str], list[MetadataChunkInfo]]:
        """Parses MP3 audio stream and strips ID3v2 and ID3v1 metadata tags."""
        if len(data) < 10:
            raise ValueError("Invalid MP3 file: insufficient data")

        stripped: list[str] = []
        findings: list[MetadataChunkInfo] = []
        data_len = len(data)
        start_offset = 0

        # Check ID3v2 tag at the start of stream
        if data[:3] == ID3_MAGIC:
            ver_major = data[3]
            flags = data[5]
            # Decode synchsafe integer (7 bits per byte across bytes 6..9)
            tag_size = (
                (data[6] << 21)
                | (data[7] << 14)
                | (data[8] << 7)
                | data[9]
            )
            has_footer = bool(flags & 0x10)
            total_tag_size = 10 + tag_size + (10 if has_footer else 0)

            if total_tag_size > data_len:
                raise ValueError("Truncated ID3v2 tag payload")

            tag_name = f"ID3v2.{ver_major}"
            stripped.append(tag_name)
            findings.append(
                MetadataChunkInfo(
                    media_format="MP3",
                    chunk_type=tag_name,
                    offset=0,
                    size=total_tag_size,
                    description=f"MP3 ID3v2.{ver_major} metadata tag ({total_tag_size} bytes)",
                )
            )
            start_offset = total_tag_size

        # Check ID3v1 tag at the end of stream (last 128 bytes starting with 'TAG')
        end_offset = data_len
        if end_offset - start_offset >= 128 and data[end_offset - 128:end_offset - 125] == b"TAG":
            stripped.append("ID3v1")
            findings.append(
                MetadataChunkInfo(
                    media_format="MP3",
                    chunk_type="ID3v1",
                    offset=end_offset - 128,
                    size=128,
                    description="MP3 ID3v1 metadata tag (128 bytes)",
                )
            )
            end_offset -= 128

        cleaned = data[start_offset:end_offset]
        return cleaned, stripped, findings

    # =========================================================================
    # WAV PARSER & SCRUBBER (RIFF/WAVE Container)
    # =========================================================================

    @classmethod
    def _parse_wav(
        cls,
        data: bytes,
    ) -> Tuple[bytes, list[str], list[MetadataChunkInfo]]:
        """Parses RIFF/WAVE container and strips LIST/INFO and ID3 metadata chunks."""
        if len(data) < 12 or data[:4] != RIFF_MAGIC or data[8:12] != WAVE_MAGIC:
            raise ValueError("Invalid WAV/RIFF header")

        data_len = len(data)
        out = bytearray(data[:12])
        offset = 12
        stripped: list[str] = []
        findings: list[MetadataChunkInfo] = []

        while offset < data_len:
            if offset + 8 > data_len:
                raise ValueError(f"Truncated WAV chunk header at offset {offset}")

            fourcc = data[offset:offset + 4]
            chunk_len = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            pad = chunk_len % 2
            total_len = 8 + chunk_len + pad

            if offset + 8 + chunk_len > data_len:
                raise ValueError(f"Truncated WAV chunk {fourcc.decode('latin1', errors='replace')} data")

            fourcc_str = fourcc.decode("latin1", errors="replace")

            # Check if chunk is LIST/INFO or embedded ID3/INFO metadata
            is_metadata = False
            meta_type = fourcc_str

            if fourcc == b"LIST":
                list_type = data[offset + 8:offset + 12] if chunk_len >= 4 else b""
                if list_type in (b"INFO", b"adtl"):
                    is_metadata = True
                    meta_type = f"LIST/{list_type.decode('latin1', errors='replace')}"
            elif fourcc.lower() in (b"id3 ", b"info"):
                is_metadata = True
                meta_type = fourcc_str.strip()

            if is_metadata:
                stripped.append(meta_type)
                findings.append(
                    MetadataChunkInfo(
                        media_format="WAV",
                        chunk_type=meta_type,
                        offset=offset,
                        size=total_len,
                        description=f"WAV audio metadata chunk: {meta_type} ({chunk_len} bytes)",
                    )
                )
            else:
                out.extend(data[offset:offset + total_len])

            offset += total_len

        # Recalculate RIFF size header
        out[4:8] = struct.pack("<I", len(out) - 8)
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
        """Analyzes binary media data and returns all detected metadata chunks."""
        fmt = (format_hint or cls.detect_format(data) or "").upper()
        if not fmt:
            raise ValueError("Unsupported or unknown media format")

        if fmt == "PNG":
            _, _, findings = cls._parse_png(data, DEFAULT_PNG_STRIP)
            return "PNG", findings
        elif fmt in ("JPEG", "JPG"):
            _, _, findings = cls._parse_jpeg(data, {JPEG_APP1, JPEG_APP2, JPEG_COM})
            return "JPEG", findings
        elif fmt == "GIF":
            _, _, findings = cls._parse_gif(data)
            return "GIF", findings
        elif fmt == "WEBP":
            _, _, findings = cls._parse_webp(data, DEFAULT_WEBP_STRIP)
            return "WEBP", findings
        elif fmt == "MP3":
            _, _, findings = cls._parse_mp3(data)
            return "MP3", findings
        elif fmt in ("WAV", "WAVE"):
            _, _, findings = cls._parse_wav(data)
            return "WAV", findings
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    @classmethod
    def scrub_bytes(
        cls,
        data: bytes,
        format_hint: Optional[str] = None,
    ) -> Tuple[bytes, list[str], str]:
        """Scrubs metadata from media bytes in memory."""
        fmt = (format_hint or cls.detect_format(data) or "").upper()
        if not fmt:
            raise ValueError("Unsupported or unknown media format")

        if fmt == "PNG":
            cleaned, stripped, _ = cls._parse_png(data, DEFAULT_PNG_STRIP)
            return cleaned, stripped, "PNG"
        elif fmt in ("JPEG", "JPG"):
            cleaned, stripped, _ = cls._parse_jpeg(data, {JPEG_APP1, JPEG_APP2, JPEG_COM})
            return cleaned, stripped, "JPEG"
        elif fmt == "GIF":
            cleaned, stripped, _ = cls._parse_gif(data)
            return cleaned, stripped, "GIF"
        elif fmt == "WEBP":
            cleaned, stripped, _ = cls._parse_webp(data, DEFAULT_WEBP_STRIP)
            return cleaned, stripped, "WEBP"
        elif fmt == "MP3":
            cleaned, stripped, _ = cls._parse_mp3(data)
            return cleaned, stripped, "MP3"
        elif fmt in ("WAV", "WAVE"):
            cleaned, stripped, _ = cls._parse_wav(data)
            return cleaned, stripped, "WAV"
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    @classmethod
    def inspect_file(cls, path: str | Path) -> Tuple[str, list[MetadataChunkInfo]]:
        """Inspects a media file on disk for metadata."""
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
        """Scrubs a media file on disk, supporting in-place or separate output."""
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
