"""Automated test suite for Sanitize Guard.

Verifies:
1. PNG chunk parsing, injection, stripping, and CRC32 integrity verification.
2. JPEG marker parsing, APP1 EXIF/GPS and COM removal, and entropy stream preservation.
3. GIF comment extension parsing and stripping with animation control preservation.
4. IP address classification (RFC 1918 private vs RFC 5737 documentation vs public).
5. Hardware MAC address validation and boundary checking.
6. Machine filesystem path detection and template placeholder exemption.
7. Cryptographic private key detection and severity rating.
8. API token and cloud credential pattern identification.
9. Dotfile redaction: .zshrc, .gitconfig, hyprland.conf, and .env templates.
10. Git commit-graph forensics and author email verification.
11. OASIS SARIF v2.1.0 schema compliance and ASCII report formatting.
12. Zero-leak self-audit ensuring no machine identities leak into tracked files.
13. WebP extended RIFF chunk parsing, EXIF/XMP stripping, and VP8X flag clearing.
14. MP3 ID3v2 and ID3v1 tag stripping with MPEG audio frame preservation.
15. WAV RIFF container parsing and LIST/INFO / ID3 metadata stripping.
16. .sanitizeignore rule parsing (globs, rule suppressions, global ignores).
17. Inline rule suppression comment parsing (# sanitize:ignore=RULE_ID).
18. Pre-commit hook installation and execution.
"""

from __future__ import annotations

import getpass
import json
import os
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

from sanitize_guard import (
    ASCIITableExporter,
    DotfileRedactor,
    MediaScrubber,
    PIIEngine,
    RuleID,
    SanitizeIgnore,
    SARIFExporter,
    Severity,
    SUPPORTED_EXTENSIONS,
)


class TestMediaScrubber(unittest.TestCase):
    """Tests for binary parsing, chunk stripping, and integrity verification."""

    @staticmethod
    def _make_png_chunk(chunk_type: bytes, data: bytes) -> bytes:
        """Constructs a valid PNG chunk with 4-byte length, type, data, and CRC32."""
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return length + chunk_type + data + crc

    def _build_synthetic_png(self, extra_chunks: list[tuple[bytes, bytes]]) -> bytes:
        """Builds a complete, valid PNG image with optional ancillary/metadata chunks."""
        sig = b"\x89PNG\r\n\x1a\n"
        ihdr_payload = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)  # 2x2 RGB 8-bit
        ihdr = self._make_png_chunk(b"IHDR", ihdr_payload)

        # 2 scanlines of 2 RGB pixels: filter byte (0) + 6 bytes per scanline
        scanlines = b"\x00\xFF\x00\x00\x00\xFF\x00" + b"\x00\x00\x00\xFF\xFF\xFF\xFF"
        idat = self._make_png_chunk(b"IDAT", zlib.compress(scanlines))
        iend = self._make_png_chunk(b"IEND", b"")

        chunks = [ihdr]
        for c_type, c_data in extra_chunks:
            chunks.append(self._make_png_chunk(c_type, c_data))
        chunks.extend([idat, iend])

        return sig + b"".join(chunks)

    def test_01_png_chunk_injection_and_detection(self) -> None:
        """Verify PNG parser identifies injected tEXt, iTXt, zTXt, eXIf, and tIME chunks."""
        extra = [
            (b"tEXt", b"Software\x00CustomEditor"),
            (b"iTXt", b"Description\x00\x00\x00\x00\x00Sensitive camera model"),
            (b"tIME", struct.pack(">HBBBBB", 2026, 10, 26, 15, 30, 0)),
            (b"eXIf", b"II*\x00\x08\x00\x00\x00GPSLatitude=37.7749"),
        ]
        raw_png = self._build_synthetic_png(extra)
        fmt, findings = MediaScrubber.inspect_bytes(raw_png)

        self.assertEqual(fmt, "PNG")
        chunk_types = [f.chunk_type for f in findings]
        self.assertIn("tEXt", chunk_types)
        self.assertIn("iTXt", chunk_types)
        self.assertIn("tIME", chunk_types)
        self.assertIn("eXIf", chunk_types)

    def test_02_png_chunk_stripping_and_crc_integrity(self) -> None:
        """Verify scrubbing removes metadata chunks while keeping critical chunks and valid CRC32."""
        extra = [
            (b"tEXt", b"Author\x00Jane Doe"),
            (b"iTXt", b"Software\x00\x00\x00\x00\x00Proprietary"),
        ]
        raw_png = self._build_synthetic_png(extra)
        cleaned_png, stripped, fmt = MediaScrubber.scrub_bytes(raw_png)

        self.assertEqual(fmt, "PNG")
        self.assertIn("tEXt", stripped)
        self.assertIn("iTXt", stripped)
        self.assertLess(len(cleaned_png), len(raw_png))

        # Inspect cleaned PNG: must have 0 findings
        _, after_findings = MediaScrubber.inspect_bytes(cleaned_png)
        self.assertEqual(len(after_findings), 0)

    def test_03_png_preserves_dimensions_and_raster(self) -> None:
        """Verify cleaned PNG retains original dimensions (2x2) and decodable IDAT."""
        raw_png = self._build_synthetic_png([(b"tEXt", b"Comment\x00Sample")])
        cleaned_png, _, _ = MediaScrubber.scrub_bytes(raw_png)

        # First chunk after signature (offset 8) must be IHDR
        self.assertEqual(cleaned_png[:8], b"\x89PNG\r\n\x1a\n")
        ihdr_type = cleaned_png[12:16]
        self.assertEqual(ihdr_type, b"IHDR")

        width, height = struct.unpack(">II", cleaned_png[16:24])
        self.assertEqual(width, 2)
        self.assertEqual(height, 2)

    def test_04_png_detects_corrupt_crc(self) -> None:
        """Verify corrupted PNG chunk CRC raises ValueError."""
        raw_png = bytearray(self._build_synthetic_png([]))
        # Corrupt last byte of IHDR CRC (offset 8 + 4 + 4 + 13 + 3 = 32)
        raw_png[32] ^= 0xFF
        with self.assertRaises(ValueError):
            MediaScrubber.inspect_bytes(bytes(raw_png))

    def test_05_jpeg_app1_exif_gps_removal(self) -> None:
        """Verify JPEG parser detects and strips APP1 EXIF/GPS marker segment."""
        soi = b"\xFF\xD8"
        app0 = b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        exif_payload = b"Exif\x00\x00II*\x00GPSLatitude=40.7128N"
        app1 = b"\xFF\xE1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload
        sos = b"\xFF\xDA\x00\x08\x01\x01\x00\x00?\x00"
        entropy = b"\x12\x34\x56"
        eoi = b"\xFF\xD9"

        raw_jpeg = soi + app0 + app1 + sos + entropy + eoi
        fmt, findings = MediaScrubber.inspect_bytes(raw_jpeg)
        self.assertEqual(fmt, "JPEG")
        self.assertTrue(any("APP1" in f.chunk_type for f in findings))

        cleaned, stripped, _ = MediaScrubber.scrub_bytes(raw_jpeg)
        self.assertTrue(any("APP1" in s for s in stripped))
        self.assertNotIn(b"GPSLatitude", cleaned)
        self.assertTrue(cleaned.startswith(b"\xFF\xD8"))
        self.assertTrue(cleaned.endswith(b"\xFF\xD9"))

    def test_06_jpeg_com_comment_removal(self) -> None:
        """Verify JPEG parser detects and strips COM (0xFE) comment marker."""
        soi = b"\xFF\xD8"
        app0 = b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        com_payload = b"Internal confidential photograph"
        com = b"\xFF\xFE" + struct.pack(">H", len(com_payload) + 2) + com_payload
        sos = b"\xFF\xDA\x00\x08\x01\x01\x00\x00?\x00"
        entropy = b"\x77\x88\x99"
        eoi = b"\xFF\xD9"

        raw_jpeg = soi + app0 + com + sos + entropy + eoi
        cleaned, stripped, _ = MediaScrubber.scrub_bytes(raw_jpeg)
        self.assertTrue(any("COM" in s for s in stripped))
        self.assertNotIn(b"Internal confidential", cleaned)

    def test_07_jpeg_preserves_stuffed_bytes_and_rst(self) -> None:
        """Verify JPEG parser correctly parses stuffed bytes (0xFF 0x00) and restart markers."""
        soi = b"\xFF\xD8"
        sos = b"\xFF\xDA\x00\x08\x01\x01\x00\x00?\x00"
        entropy_with_stuffing = b"\xAA\xFF\x00\xBB\xFF\xD0\xCC"  # FF 00 stuffed byte, FF D0 RST0
        eoi = b"\xFF\xD9"

        raw_jpeg = soi + sos + entropy_with_stuffing + eoi
        cleaned, stripped, _ = MediaScrubber.scrub_bytes(raw_jpeg)
        self.assertIn(b"\xAA\xFF\x00\xBB\xFF\xD0\xCC", cleaned)
        self.assertTrue(cleaned.endswith(b"\xFF\xD9"))

    def test_08_gif_comment_extension_stripping(self) -> None:
        """Verify GIF comment extension blocks (0x21 0xFE) are parsed and stripped."""
        header = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xFF\xFF\xFF"
        gce = b"\x21\xF9\x04\x00\x00\x00\x00\x00"
        comment_text = b"Secret Location"
        comment = b"\x21\xFE" + bytes([len(comment_text)]) + comment_text + b"\x00"
        img = b"\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00"
        trailer = b"\x3B"

        raw_gif = header + gce + comment + img + trailer
        fmt, findings = MediaScrubber.inspect_bytes(raw_gif)
        self.assertEqual(fmt, "GIF")
        self.assertEqual(len(findings), 1)

        cleaned, stripped, _ = MediaScrubber.scrub_bytes(raw_gif)
        self.assertTrue(any("Comment" in s for s in stripped))
        self.assertNotIn(b"Secret Location", cleaned)
        self.assertTrue(cleaned.startswith(b"GIF89a"))
        self.assertTrue(cleaned.endswith(b"\x3B"))

    def test_09_gif_preserves_graphic_control_and_lzw(self) -> None:
        """Verify GIF graphic control extensions and image descriptors are preserved."""
        header = b"GIF89a\x01\x00\x01\x00\x00\x00\x00"
        gce = b"\x21\xF9\x04\x05\x0A\x00\x01\x00"  # Delay time 10, transparent index 1
        img = b"\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00"
        trailer = b"\x3B"

        raw_gif = header + gce + img + trailer
        cleaned, stripped, _ = MediaScrubber.scrub_bytes(raw_gif)
        self.assertEqual(len(stripped), 0)
        self.assertIn(gce, cleaned)
        self.assertIn(img, cleaned)

    def test_23_webp_exif_xmp_stripping_and_vp8x_flag_update(self) -> None:
        """Verify WebP EXIF and XMP chunks are stripped, and VP8X flag bits are cleared."""
        # Construct synthetic WebP: RIFF + size + WEBP + VP8X + EXIF + VP8 + XMP
        # VP8X: 10 bytes payload. Byte 0 has flags: 0x08 (EXIF) | 0x04 (XMP) = 0x0C
        vp8x_payload = b"\x0C\x00\x00\x00\x40\x00\x00\x40\x00\x00"
        vp8x_chunk = b"VP8X" + struct.pack("<I", len(vp8x_payload)) + vp8x_payload

        exif_payload = b"Exif\x00\x00II*\x00GPSLatitude=40.7128N"
        exif_pad = b"\x00" if len(exif_payload) % 2 else b""
        exif_chunk = b"EXIF" + struct.pack("<I", len(exif_payload)) + exif_payload + exif_pad

        vp8_payload = b"\x9d\x01\x2a\x40\x00\x40\x00\x00\x00\x00"
        vp8_pad = b"\x00" if len(vp8_payload) % 2 else b""
        vp8_chunk = b"VP8 " + struct.pack("<I", len(vp8_payload)) + vp8_payload + vp8_pad

        xmp_payload = b"<x:xmpmeta>ConfidentialMetadata</x:xmpmeta>"
        xmp_pad = b"\x00" if len(xmp_payload) % 2 else b""
        xmp_chunk = b"XMP " + struct.pack("<I", len(xmp_payload)) + xmp_payload + xmp_pad

        chunks = vp8x_chunk + exif_chunk + vp8_chunk + xmp_chunk
        raw_webp = b"RIFF" + struct.pack("<I", len(chunks) + 4) + b"WEBP" + chunks

        fmt, findings = MediaScrubber.inspect_bytes(raw_webp)
        self.assertEqual(fmt, "WEBP")
        found_chunks = [f.chunk_type for f in findings]
        self.assertIn("EXIF", found_chunks)
        self.assertIn("XMP", found_chunks)

        cleaned_webp, stripped, clean_fmt = MediaScrubber.scrub_bytes(raw_webp)
        self.assertEqual(clean_fmt, "WEBP")
        self.assertIn("EXIF", stripped)
        self.assertIn("XMP", stripped)
        self.assertNotIn(b"GPSLatitude", cleaned_webp)
        self.assertNotIn(b"ConfidentialMetadata", cleaned_webp)
        self.assertIn(b"VP8 ", cleaned_webp)

        # Check RIFF size header
        expected_size = len(cleaned_webp) - 8
        riff_size = struct.unpack("<I", cleaned_webp[4:8])[0]
        self.assertEqual(riff_size, expected_size)

        # Check VP8X flags: byte 12..16 is 'VP8X', 16..20 is len, 20 is flags byte
        self.assertEqual(cleaned_webp[12:16], b"VP8X")
        flags_byte = cleaned_webp[20]
        self.assertEqual(flags_byte & 0x08, 0, "EXIF flag bit should be cleared")
        self.assertEqual(flags_byte & 0x04, 0, "XMP flag bit should be cleared")

        # Inspect cleaned WebP: should have zero findings
        _, after_findings = MediaScrubber.inspect_bytes(cleaned_webp)
        self.assertEqual(len(after_findings), 0)

    def test_24_mp3_id3v2_and_id3v1_stripping(self) -> None:
        """Verify MP3 ID3v2 header and ID3v1 trailer tags are stripped while audio frames remain."""
        # Construct synthetic ID3v2.3 tag
        id3v2_payload = b"TIT2\x00\x00\x00\x0B\x00\x00\x00SecretSong"
        tag_len = len(id3v2_payload)
        synchsafe = bytes([
            (tag_len >> 21) & 0x7F,
            (tag_len >> 14) & 0x7F,
            (tag_len >> 7) & 0x7F,
            tag_len & 0x7F,
        ])
        id3v2_header = b"ID3\x03\x00\x00" + synchsafe
        id3v2_tag = id3v2_header + id3v2_payload

        # Audio frame sync (MPEG audio frame)
        audio_frame = b"\xFF\xFB\x90\x64" + b"\x00" * 32

        # ID3v1 trailer (128 bytes starting with TAG)
        id3v1_tag = b"TAG" + b"SecretTitle".ljust(30, b"\x00") + b"Artist".ljust(30, b"\x00") + b"\x00" * 65

        raw_mp3 = id3v2_tag + audio_frame + id3v1_tag

        fmt, findings = MediaScrubber.inspect_bytes(raw_mp3)
        self.assertEqual(fmt, "MP3")
        found_tags = [f.chunk_type for f in findings]
        self.assertIn("ID3v2.3", found_tags)
        self.assertIn("ID3v1", found_tags)

        cleaned_mp3, stripped, clean_fmt = MediaScrubber.scrub_bytes(raw_mp3)
        self.assertEqual(clean_fmt, "MP3")
        self.assertIn("ID3v2.3", stripped)
        self.assertIn("ID3v1", stripped)
        self.assertNotIn(b"SecretSong", cleaned_mp3)
        self.assertNotIn(b"SecretTitle", cleaned_mp3)
        self.assertEqual(cleaned_mp3, audio_frame)

        # Inspect cleaned MP3
        _, after_findings = MediaScrubber.inspect_bytes(cleaned_mp3)
        self.assertEqual(len(after_findings), 0)

    def test_25_wav_list_info_and_id3_stripping(self) -> None:
        """Verify WAV RIFF container strips LIST/INFO and id3 chunks while preserving audio."""
        fmt_payload = b"\x01\x00\x01\x00\x44\xAC\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00"
        fmt_chunk = b"fmt " + struct.pack("<I", len(fmt_payload)) + fmt_payload

        # LIST/INFO chunk
        info_sub = b"INAM\x08\x00\x00\x00SecretSong\x00"
        list_payload = b"INFO" + info_sub
        list_pad = b"\x00" if len(list_payload) % 2 else b""
        list_chunk = b"LIST" + struct.pack("<I", len(list_payload)) + list_payload + list_pad

        # id3 chunk
        id3_payload = b"ID3\x03\x00\x00\x00\x00\x00\x0A" + b"\x00" * 10
        id3_pad = b"\x00" if len(id3_payload) % 2 else b""
        id3_chunk = b"id3 " + struct.pack("<I", len(id3_payload)) + id3_payload + id3_pad

        data_payload = b"\x00\x01\x00\x02" * 16
        data_chunk = b"data" + struct.pack("<I", len(data_payload)) + data_payload

        chunks = fmt_chunk + list_chunk + id3_chunk + data_chunk
        raw_wav = b"RIFF" + struct.pack("<I", len(chunks) + 4) + b"WAVE" + chunks

        fmt, findings = MediaScrubber.inspect_bytes(raw_wav)
        self.assertEqual(fmt, "WAV")
        found = [f.chunk_type for f in findings]
        self.assertTrue(any("LIST" in t for t in found))
        self.assertTrue(any("id3" in t.lower() for t in found))

        cleaned_wav, stripped, clean_fmt = MediaScrubber.scrub_bytes(raw_wav)
        self.assertEqual(clean_fmt, "WAV")
        self.assertNotIn(b"SecretSong", cleaned_wav)
        self.assertIn(b"fmt ", cleaned_wav)
        self.assertIn(b"data", cleaned_wav)
        self.assertIn(data_payload, cleaned_wav)

        expected_size = len(cleaned_wav) - 8
        riff_size = struct.unpack("<I", cleaned_wav[4:8])[0]
        self.assertEqual(riff_size, expected_size)

        _, after_findings = MediaScrubber.inspect_bytes(cleaned_wav)
        self.assertEqual(len(after_findings), 0)


class TestPIIEngine(unittest.TestCase):
    """Tests for PII identification, IP classification, and credential detection."""

    def setUp(self) -> None:
        self.engine = PIIEngine(target_usernames=["targetuser"], target_hostnames=["labbox"])

    def test_10_ip_rfc1918_classification(self) -> None:
        """Verify RFC 1918 private IPv4 addresses are flagged as leaks with replacements."""
        samples = [
            "10.0.0.1",
            "172.16.50.12",
            "192.168.1.100",
            "100.64.0.1",  # CGNAT
        ]
        for ip in samples:
            findings = self.engine.scan_text(f"SERVER_IP={ip}")
            matched = [f for f in findings if f.matched_text == ip]
            self.assertEqual(len(matched), 1, f"Failed for {ip}")
            self.assertEqual(matched[0].rule_id, RuleID.RFC1918_PRIVATE_IP)
            self.assertTrue(matched[0].is_leak)
            self.assertEqual(matched[0].severity, Severity.MEDIUM)
            self.assertIsNotNone(matched[0].replacement)
            self.assertTrue(matched[0].replacement.startswith("198.51.100."))

    def test_11_ip_rfc5737_documentation_classification(self) -> None:
        """Verify RFC 5737 documentation IPs are classified as safe INFO items."""
        doc_ips = [
            "192.0.2.1",     # TEST-NET-1
            "198.51.100.45", # TEST-NET-2
            "203.0.113.88",  # TEST-NET-3
        ]
        for ip in doc_ips:
            findings = self.engine.scan_text(f"DOC_ENDPOINT={ip}")
            matched = [f for f in findings if f.matched_text == ip]
            self.assertEqual(len(matched), 1, f"Failed for {ip}")
            self.assertEqual(matched[0].rule_id, RuleID.RFC5737_DOC_IP)
            self.assertFalse(matched[0].is_leak)
            self.assertEqual(matched[0].severity, Severity.INFO)

    def test_12_ip_public_classification(self) -> None:
        """Verify public IPv4 addresses are classified as PUBLIC_IP."""
        findings = self.engine.scan_text("DNS_PRIMARY=8.8.8.8\nCLOUDFLARE=1.1.1.1")
        public_findings = [f for f in findings if f.rule_id == RuleID.PUBLIC_IP]
        self.assertEqual(len(public_findings), 2)
        self.assertTrue(all(f.is_leak for f in public_findings))

    def test_13_mac_address_detection(self) -> None:
        """Verify MAC addresses are detected and broadcast/zeros are ignored."""
        text = "eth0: 00:1A:2B:3C:4D:5E, wlan0: a4-c3-f0-8e-12-44, br: FF:FF:FF:FF:FF:FF, zero: 00:00:00:00:00:00"
        findings = self.engine.scan_text(text)
        mac_findings = [f for f in findings if f.rule_id == RuleID.MAC_ADDRESS]
        self.assertEqual(len(mac_findings), 2)
        matches = [f.matched_text for f in mac_findings]
        self.assertIn("00:1A:2B:3C:4D:5E", matches)
        self.assertIn("a4-c3-f0-8e-12-44", matches)
        self.assertNotIn("FF:FF:FF:FF:FF:FF", matches)

    def test_14_machine_path_detection(self) -> None:
        """Verify machine paths are detected while template placeholders are ignored."""
        p_dev = "/home" + "/developer/bin"
        p_mac = "/Users" + "/johndoe/Library"
        text = (
            f"export PATH={p_dev}:$PATH\n"
            "export SAFE_TEMPLATE=/home/<user>/scripts\n"
            "export GENERIC_PATH=/home/username/project\n"
            f"export MAC_PATH={p_mac}\n"
        )
        findings = self.engine.scan_text(text)
        path_findings = [f for f in findings if f.rule_id == RuleID.MACHINE_PATH]
        self.assertEqual(len(path_findings), 2)
        paths = [f.matched_text for f in path_findings]
        self.assertIn(p_dev, paths)
        self.assertIn(p_mac, paths)
        self.assertNotIn("/home/<user>/scripts", paths)

    def test_15_private_key_detection(self) -> None:
        """Verify cryptographic private keys are flagged with CRITICAL severity."""
        pfx_k = "-----BEGIN " + "RSA PRIVATE KEY-----\n"
        sfx_k = "-----END " + "RSA PRIVATE KEY-----\n"
        key_sample = (
            pfx_k +
            "MIIEowIBAAKCAQEA0Y1l...\n" +
            sfx_k
        )
        findings = self.engine.scan_text(key_sample)
        key_findings = [f for f in findings if f.rule_id == RuleID.PRIVATE_KEY]
        self.assertEqual(len(key_findings), 1)
        self.assertEqual(key_findings[0].severity, Severity.CRITICAL)

    def test_16_api_token_detection(self) -> None:
        """Verify GitHub tokens, AWS keys, OpenAI keys, and Slack tokens are flagged."""
        tok_gh = "gh" + "p_" + "0123456789abcdefghijklmnopqrstuvwxyz0123456789"
        tok_aws = "AK" + "IA" + "1234567890ABCDEF"
        tok_sk = "sk-" + "live_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        tok_slack = "xo" + "xb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
        text = (
            f"GH_TOKEN={tok_gh}\n"
            f"AWS_KEY={tok_aws}\n"
            f"OPENAI_KEY={tok_sk}\n"
            f"SLACK_KEY={tok_slack}\n"
        )
        findings = self.engine.scan_text(text)
        token_findings = [f for f in findings if f.rule_id == RuleID.API_TOKEN]
        self.assertEqual(len(token_findings), 4)

    def test_26_sanitizeignore_parser(self) -> None:
        """Verify .sanitizeignore parses path globs, specific rule suppressions, and global rules."""
        ignore_rules = [
            "# Comments and blank lines should be ignored",
            "",
            "*.log",
            "build/",
            "legacy/config.sh:SAN-001",
            "fixtures/token.txt:SAN-005",
            "ignore-rule:SAN-003",
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_path = Path(tmpdir) / ".sanitizeignore"
            ignore_path.write_text("\n".join(ignore_rules), encoding="utf-8")

            ignore = SanitizeIgnore.from_file(ignore_path)
            self.assertTrue(ignore.is_path_ignored("debug.log"))
            self.assertTrue(ignore.is_path_ignored("build/artifact.bin"))
            self.assertFalse(ignore.is_path_ignored("src/app.py"))

            # Specific rule suppression on file
            self.assertTrue(ignore.is_rule_ignored_for_path("legacy/config.sh", "SAN-001"))
            self.assertFalse(ignore.is_rule_ignored_for_path("legacy/config.sh", "SAN-002"))
            self.assertTrue(ignore.is_rule_ignored_for_path("fixtures/token.txt", "SAN-005"))

            # Global rule suppression
            self.assertTrue(ignore.is_rule_ignored_for_path("anywhere.py", "SAN-003"))
            self.assertFalse(ignore.is_rule_ignored_for_path("anywhere.py", "SAN-001"))

            # Test scanning file with SanitizeIgnore applied
            p_synth = "/home" + "/synthdev/bin"
            test_file = Path(tmpdir) / "legacy" / "config.sh"
            test_file.parent.mkdir(parents=True, exist_ok=True)
            test_file.write_text(f"export PATH={p_synth}\nexport IP=192.168.1.50\n", encoding="utf-8")

            findings = self.engine.scan_file(test_file, ignore=ignore)
            # SAN-001 is suppressed for legacy/config.sh, but RFC1918 private IP (SAN-004) is not
            rule_ids = [f.rule_id.value for f in findings]
            self.assertNotIn(RuleID.MACHINE_PATH.value, rule_ids)
            self.assertIn(RuleID.RFC1918_PRIVATE_IP.value, rule_ids)

    def test_27_inline_rule_suppression(self) -> None:
        """Verify inline comments (# sanitize:ignore and # sanitize:ignore=RULE_ID) suppress findings."""
        tok_gh = "gh" + "p_" + "0123456789abcdefghijklmnopqrstuvwxyz0123456789"
        p_synth = "/home" + "/synthdev/bin"

        # 1. Line with specific rule suppression
        line1 = f"API_KEY = '{tok_gh}'  # sanitize:ignore=SAN-009"
        findings1 = self.engine.scan_line(line1, line_number=1)
        self.assertEqual(len(findings1), 0)

        # 2. Line with generic suppression (all rules)
        line2 = f"PATH = '{p_synth}'  # sanitize:ignore"
        findings2 = self.engine.scan_line(line2, line_number=2)
        self.assertEqual(len(findings2), 0)

        # 3. Line with non-matching suppression
        line3 = f"PATH = '{p_synth}'  # sanitize:ignore=SAN-009"
        findings3 = self.engine.scan_line(line3, line_number=3)
        self.assertEqual(len(findings3), 1)
        self.assertEqual(findings3[0].rule_id, RuleID.MACHINE_PATH)

        # 4. Multiline text scanning with mixed comments
        text = (
            f"KEY1 = '{tok_gh}'  # sanitize:ignore=SAN-009\n"
            f"KEY2 = '{tok_gh}'\n"
        )
        findings4 = self.engine.scan_text(text)
        self.assertEqual(len(findings4), 1)
        self.assertEqual(findings4[0].line_number, 2)


class TestDotfileRedactor(unittest.TestCase):
    """Tests for dotfile transformations, gitconfig sanitization, and WM configurations."""

    def setUp(self) -> None:
        self.redactor = DotfileRedactor(
            default_git_name="1MEshh",
            default_git_email="152591660+1MEshh@users.noreply.github.com",
        )

    def test_17_dotfile_redactor_zshrc(self) -> None:
        """Verify .zshrc paths, private IPs, and API tokens are cleanly transformed."""
        p_synth = "/home" + "/synthdev/bin"
        tok_sk = "sk-" + "live_" + "sampletoken12345678901234567890"
        content = (
            f"export PATH={p_synth}:$PATH\n"
            "export CLUSTER=192.168.1.100\n"
            f"export OPENAI_API_KEY=\"{tok_sk}\"\n"
        )
        res = self.redactor.redact_text(content, filename=".zshrc")
        self.assertTrue(res.is_modified)
        self.assertNotIn(p_synth, res.redacted_content)
        self.assertIn("${HOME}/bin", res.redacted_content)
        self.assertNotIn("192.168.1.100", res.redacted_content)
        self.assertIn("198.51.100.100", res.redacted_content)
        self.assertIn("<REDACTED_API_SECRET>", res.redacted_content)

    def test_18_dotfile_redactor_gitconfig(self) -> None:
        """Verify .gitconfig user details and signing key are transformed to noreply."""
        content = (
            "[user]\n"
            "\tname = Alice Smith\n"
            "\temail = alice@company.internal\n"
            "\tsigningkey = B78A9C1234567890\n"
        )
        res = self.redactor.redact_text(content, filename=".gitconfig")
        self.assertTrue(res.is_modified)
        self.assertIn("name = 1MEshh", res.redacted_content)
        self.assertIn("email = 152591660+1MEshh@users.noreply.github.com", res.redacted_content)
        self.assertIn("<YOUR_GPG_KEY_ID>", res.redacted_content)

    def test_19_dotfile_redactor_hyprland(self) -> None:
        """Verify hyprland monitor hardware descriptors and exec paths are redacted."""
        exec_script = "/home" + "/synthdev/.config/hypr/scripts/launch.sh"
        content = (
            "monitor=desc:LG Electronics 27GL850 123456,2560x1440@144,0x0,1\n"
            f"exec-once = {exec_script}\n"
        )
        res = self.redactor.redact_text(content, filename="hyprland.conf")
        self.assertTrue(res.is_modified)
        self.assertIn("<MONITOR_HARDWARE_DESCRIPTION>", res.redacted_content)
        self.assertNotIn("27GL850", res.redacted_content)
        self.assertIn("~/.config/hypr/scripts/launch.sh", res.redacted_content)


class TestAuditAndSARIF(unittest.TestCase):
    """Tests for Git forensics, SARIF v2.1.0 schema generation, and zero-leak compliance."""

    def test_20_git_history_forensics(self) -> None:
        """Verify check-git verifies commit history and enforces noreply addresses."""
        res = subprocess.run(
            ["python3", "-m", "sanitize_guard.cli", "check-git", "--commits=10", "--fail-on-leak"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, f"Git history forensics failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("Zero personal emails, paths, or secrets detected", res.stdout)

    def test_21_sarif_v2_schema_export(self) -> None:
        """Verify SARIF generator creates valid OASIS SARIF v2.1.0 JSON object."""
        engine = PIIEngine()
        p_cfg = "/home" + "/developer/bin"
        findings = engine.scan_text(f"export PATH={p_cfg}", file_path="config.sh")
        sarif_json = SARIFExporter.to_json(findings)
        sarif_obj = json.loads(sarif_json)

        self.assertEqual(sarif_obj["version"], "2.1.0")
        self.assertIn("runs", sarif_obj)
        self.assertEqual(len(sarif_obj["runs"]), 1)
        run = sarif_obj["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "sanitize-guard")
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["ruleId"], "SAN-001")

        # Also verify ASCII Table Exporter does not crash
        ascii_table = ASCIITableExporter().format_table(findings)
        self.assertIn("SAN-001", ascii_table)

    def test_22_zero_leak_check_on_repository(self) -> None:
        """Ensure no local OS usernames or machine paths leak into tracked source files."""
        current_user = getpass.getuser()
        if not current_user or current_user in ("root", "runner"):
            return

        # Check repository source files
        repo_root = Path(__file__).resolve().parent.parent
        src_files = list((repo_root / "sanitize_guard").glob("*.py"))
        for py_file in src_files:
            content = py_file.read_text(encoding="utf-8")
            self.assertNotIn(
                current_user,
                content,
                f"Local username '{current_user}' leaked into source file: {py_file}",
            )

    def test_28_install_hook_command(self) -> None:
        """Verify install-hook subcommand writes an executable zero-leak pre-commit hook."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir)
            git_dir = repo_dir / ".git"
            git_dir.mkdir()

            res = subprocess.run(
                ["python3", "-m", "sanitize_guard.cli", "install-hook", "--path", str(repo_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, f"install-hook failed:\n{res.stdout}\n{res.stderr}")
            hook_file = git_dir / "hooks" / "pre-commit"
            self.assertTrue(hook_file.is_file(), "pre-commit hook file was not created")
            self.assertTrue(os.access(hook_file, os.X_OK), "pre-commit hook is not executable")

            content = hook_file.read_text(encoding="utf-8")
            self.assertIn('RUNNER="sanitize-guard"', content)
            self.assertIn("$RUNNER scan .", content)
            self.assertIn("$RUNNER check-git", content)


if __name__ == "__main__":
    unittest.main()
