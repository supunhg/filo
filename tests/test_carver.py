import pytest
from filo.carver import CarverEngine, CarvedFile, StreamCarver


@pytest.fixture
def carver():
    return CarverEngine()


def test_carve_single_png():
    carver = CarverEngine()

    png_header = bytes.fromhex("89504E470D0A1A0A")
    png_data = png_header + b"\x00" * 1000 + b"IEND\xae\x42\x60\x82"

    junk = b"\xff" * 500
    combined = junk + png_data + junk

    carved = carver.carve_data(combined, min_size=100)

    assert len(carved) >= 1
    assert any(c.format == "png" for c in carved)

    png_carved = [c for c in carved if c.format == "png"][0]
    assert png_carved.offset == 500
    assert png_carved.confidence > 0.5


def test_carve_multiple_files():
    carver = CarverEngine()

    png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 500 + b"IEND\xae\x42\x60\x82"
    jpeg = bytes.fromhex("FFD8FFE0") + b"\x00" * 300 + b"\xff\xd9"
    zip_data = bytes.fromhex("504B0304") + b"\x00" * 400

    combined = b"\xff" * 100 + png + b"\x00" * 50 + jpeg + b"\x00" * 50 + zip_data

    carved = carver.carve_data(combined, min_size=100)

    assert len(carved) >= 1

    formats = [c.format for c in carved]
    assert "png" in formats or "jpeg" in formats or "zip" in formats


def test_carve_min_size_filter():
    carver = CarverEngine()

    small_png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 50
    large_png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 2000 + b"IEND\xae\x42\x60\x82"

    combined = small_png + b"\xff" * 100 + large_png

    carved = carver.carve_data(combined, min_size=1000)

    assert all(c.size >= 1000 for c in carved)


def test_carve_with_overlapping_signatures():
    carver = CarverEngine()

    data = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 1000 + b"IEND\xae\x42\x60\x82"

    carved = carver.carve_data(data, min_size=100)

    assert len(carved) >= 1
    assert carved[0].format == "png"


def test_carved_file_save(tmp_path):
    carved = CarvedFile(
        offset=100,
        size=500,
        format="png",
        confidence=0.95,
        data=b"\x89PNG\r\n\x1a\n" + b"\x00" * 492,
    )

    output_file = tmp_path / "test.png"
    carved.save(output_file)

    assert output_file.exists()
    assert output_file.read_bytes() == carved.data


def test_carve_file(tmp_path):
    test_file = tmp_path / "test.bin"

    png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 1000 + b"IEND\xae\x42\x60\x82"
    test_file.write_bytes(b"\xff" * 200 + png + b"\xff" * 200)

    carver = CarverEngine()
    carved = carver.carve_file(test_file, min_size=100)

    assert len(carved) >= 1
    assert any(c.format == "png" for c in carved)


def test_stream_carver():
    stream = StreamCarver(buffer_size=2048)

    png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 1000 + b"IEND\xae\x42\x60\x82"

    chunk1 = b"\xff" * 100 + png[:500]
    chunk2 = png[500:] + b"\xff" * 100

    result1 = stream.feed(chunk1)
    result2 = stream.feed(chunk2)
    final = stream.finalize()

    all_carved = result1 + result2 + final

    assert len(all_carved) >= 1
    assert any(c.format == "png" for c in all_carved)


def test_estimate_file_size_png():
    carver = CarverEngine()

    png_data = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 500 + b"IEND\xae\x42\x60\x82"

    result = carver.analyzer.analyze(png_data)
    size = carver._estimate_file_size(png_data, result)

    assert size > 0
    assert size <= len(png_data)


def test_carve_jpeg_with_footer():
    carver = CarverEngine()

    jpeg = bytes.fromhex("FFD8FFE0") + b"\x00" * 800 + b"\xff\xd9"
    combined = b"\xff" * 100 + jpeg + b"\x00" * 100

    carved = carver.carve_data(combined, min_size=100)

    jpeg_files = [c for c in carved if c.format == "jpeg"]
    if jpeg_files:
        assert jpeg_files[0].size >= 800


def test_carve_empty_data():
    carver = CarverEngine()
    carved = carver.carve_data(b"", min_size=100)
    assert len(carved) == 0


def test_carve_no_valid_files():
    carver = CarverEngine()
    carved = carver.carve_data(b"\x00" * 5000, min_size=100)
    assert len(carved) == 0


def test_carved_file_metadata():
    carver = CarverEngine()

    png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 1000 + b"IEND\xae\x42\x60\x82"
    carved = carver.carve_data(png, min_size=100)

    if carved:
        assert carved[0].metadata is not None
        assert "evidence" in carved[0].metadata


def test_signature_index_creation():
    carver = CarverEngine()

    assert len(carver.signatures) > 0

    png_sig = bytes.fromhex("89504E470D0A1A0A")
    assert png_sig in carver.signatures
    assert "png" in carver.signatures[png_sig]
