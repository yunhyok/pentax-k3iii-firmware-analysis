"""Synthetic block preservation and output transaction tests with no firmware inputs."""

from contextlib import contextmanager
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from inspect_firmware import decode
from tools.repack_changed_blocks import preserve_blocks, write_outputs


def stored_piece(payload):
    return struct.pack(">H", 0x8000 | len(payload)) + payload


def lz_piece(flags, tokens):
    body = struct.pack(">H", flags) + tokens + b"\0\0"
    return struct.pack(">H", len(body)) + body


def history_stream():
    history = bytes(range(256)) * 32
    # 0xf8ff is length 3, distance 8191; flags select two copies and two literals.
    return stored_piece(history) + lz_piece(0xc000, b"\xf8\xff\xf8\xffXY") + b"\0\0"


def raw_piece(stream, block):
    return stream[block["input_start"]:block["input_end"]]


class BlockPreservationTests(unittest.TestCase):
    def check_decoded(self, stream, expected):
        decoded, end, blocks = decode(stream, 0, len(expected))
        self.assertEqual(decoded, expected)
        self.assertEqual(end, len(stream))
        self.assertEqual(len(stream) % 4, 0)
        return blocks

    def test_noop_preserves_original_stream_including_lz_bytes(self):
        stream = history_stream()
        before = bytes(range(256)) * 32 + b"\x01\x02\x03\x04\x05\x06XY"
        self.assertEqual((len(stream), len(before)), (8208, 8200))
        # The block offsets normally address a larger package, not a zero-based stream.
        header = b"synthetic header".ljust(128, b"\0")
        source = header + stream + b"synthetic footer"
        decoded, end, blocks = decode(source, len(header), len(before))
        self.assertEqual(decoded, before)
        self.assertEqual(end, len(header) + len(stream))
        result, report = preserve_blocks(source, before, before, blocks)
        self.assertEqual(result, stream)
        self.assertEqual(report["replaced_original_blocks"], [])
        self.assertEqual(report["preserved_original_blocks"], 2)
        self.assertIsNone(report["parity_extra_block"])
        self.assertIsNone(report["split_extra_block"])

    def test_change_8192_bytes_back_preserves_lz_but_8191_back_replaces_it(self):
        source = history_stream()
        before, _, blocks = decode(source, 0)
        for index, replaced in ((0, [0]), (1, [0, 1])):
            with self.subTest(distance=8192 - index):
                target = before[:index] + b"!" + before[index + 1:]
                result, report = preserve_blocks(source, before, target, blocks)
                actual = self.check_decoded(result, target)
                self.assertEqual(report["replaced_original_blocks"], replaced)
                if index == 0:
                    self.assertEqual(actual[-1]["kind"], "lz")
                    self.assertEqual(raw_piece(result, actual[-1]), raw_piece(source, blocks[-1]))
                else:
                    self.assertTrue(all(block["kind"] == "stored" for block in actual))
                    self.assertEqual(result, stored_piece(target[:1]) + stored_piece(target[1:8192])
                                     + stored_piece(target[8192:]) + b"\0\0")

    def test_overlapping_copy_replaced_when_its_history_changes(self):
        # A length-4 distance-1 copy expands the last byte four times, including its own output.
        source = stored_piece(b"ABCD") + lz_piece(0x8000, b"\x01\x01") + b"\0\0"
        before = b"ABCDDDDD"
        blocks = self.check_decoded(source, before)
        target = b"ABCZDDDD"  # Leaving the original token would incorrectly emit four Z bytes.
        result, report = preserve_blocks(source, before, target, blocks)
        self.check_decoded(result, target)
        self.assertEqual(report["replaced_original_blocks"], [0, 1])

    def test_odd_parity_conversion_and_modulo_four_split(self):
        copy_then_literal = lz_piece(0x8000, b"\x00\x04Z")
        source = (stored_piece(b"ABCD") + copy_then_literal + stored_piece(b"M" * 8192)
                  + copy_then_literal + b"\0\0")
        before = b"ABCDABCZ" + b"M" * 8192 + b"MMMZ"
        blocks = self.check_decoded(source, before)
        target = b"!" + before[1:]
        result, report = preserve_blocks(source, before, target, blocks)
        self.check_decoded(result, target)
        self.assertEqual((len(source), len(result)), (8220, 8216))
        self.assertEqual(report["parity_extra_block"], 3)
        self.assertEqual(report["split_extra_block"], 0)
        self.assertEqual(report["replaced_original_blocks"], [0, 1, 2, 3])
        self.assertEqual(result, stored_piece(b"!") + stored_piece(b"BCD") + stored_piece(b"ABCZ")
                         + stored_piece(b"M" * 8192) + stored_piece(b"MMMZ") + b"\0\0")

    def test_large_original_lz_block_replaced_with_multiple_stored_chunks(self):
        # The extended token copies 10 + 128*255 + 118 bytes at distance 1.
        long_copy = b"\x07\x01" + b"\xff" * 128 + b"\x76"
        source = stored_piece(b"ABCD") + lz_piece(0xc000, long_copy + b"\x00\x01Z") + b"\0\0"
        before = b"ABC" + b"D" * (1 + 32768 + 3) + b"Z"
        blocks = self.check_decoded(source, before)
        target = before[:4] + b"!" + before[5:]
        result, report = preserve_blocks(source, before, target, blocks)
        actual = self.check_decoded(result, target)
        self.assertEqual(report["replaced_original_blocks"], [1])
        self.assertEqual([(b["kind"], b["output_end"] - b["output_start"]) for b in actual],
                         [("stored", 4), ("stored", 0x6000), ("stored", 8196)])
        self.assertEqual(raw_piece(result, actual[0]), raw_piece(source, blocks[0]))

    def test_rejects_invalid_decoded_coverage_or_length(self):
        source = history_stream()
        before, _, blocks = decode(source, 0)
        cases = (
            (before[:-1], blocks, "Same-size"),
            (before, [], "Same-size nonempty"),
            (before, blocks[:1], "Incomplete decoded block coverage"),
            (before, [blocks[0], {**blocks[1], "output_start": 8193}], "Invalid decoded block coverage"),
            (before, [blocks[0], {**blocks[1], "output_start": 8191}], "Invalid decoded block coverage"),
            (before, [blocks[0], {**blocks[1], "output_end": len(before) + 1}], "Invalid decoded block coverage"),
        )
        for target, metadata, error in cases:
            with self.subTest(target_length=len(target), last_block=metadata[-1:] or None):
                with self.assertRaisesRegex(ValueError, error):
                    preserve_blocks(source, before, target, metadata)


class OutputTransactionTests(unittest.TestCase):
    def test_outputs_are_written_once_and_existing_directory_is_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "result"
            write_outputs(directory, b"first candidate", {"passed": True})
            with self.assertRaises(FileExistsError):
                write_outputs(directory, b"second candidate", {"passed": False})
            self.assertEqual((directory / "candidate.bin").read_bytes(), b"first candidate")
            self.assertEqual(json.loads((directory / "evidence.json").read_text(encoding="utf-8")), {"passed": True})

    def test_second_file_short_write_rolls_back_both_outputs(self):
        original_open = Path.open

        @contextmanager
        def short_evidence(path, *args, **kwargs):
            with original_open(path, *args, **kwargs) as output:
                self.assertTrue((path.parent / "candidate.bin").is_file())
                yield SimpleNamespace(write=lambda data: output.write(data[:1]))

        def open_with_fault(path, *args, **kwargs):
            if path.name == "evidence.json":
                return short_evidence(path, *args, **kwargs)
            return original_open(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "result"
            with patch.object(Path, "open", open_with_fault):
                with self.assertRaisesRegex(ValueError, "Short output write"):
                    write_outputs(directory, b"candidate", {"passed": True})
            self.assertFalse(directory.exists())


if __name__ == "__main__":
    unittest.main()
