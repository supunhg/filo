import time
import random
from pathlib import Path

from filo import Analyzer


def benchmark_analysis():
    print("=== Performance Benchmark ===\n")

    analyzer = Analyzer(use_ml=False)

    test_files = {
        "PNG (small)": bytes.fromhex("89504E470D0A1A0A0000000D49484452") + b"\x00" * 1000,
        "JPEG": bytes.fromhex("FFD8FFE0") + b"\x00" * 5000,
        "PDF": b"%PDF-1.7\r\n" + b"\x00" * 10000,
        "ZIP": bytes.fromhex("504B0304") + b"\x00" * 2000,
        "ELF": bytes.fromhex("7F454C46") + b"\x00" * 8000,
        "Random": bytes([random.randint(0, 255) for _ in range(50000)]),
    }

    print(f"Testing {len(test_files)} different file types...\n")

    total_time = 0
    for name, data in test_files.items():
        start = time.perf_counter()
        for _ in range(100):
            result = analyzer.analyze(data)
        end = time.perf_counter()

        avg_time = (end - start) / 100 * 1000
        total_time += end - start

        print(f"{name:20s} | {result.primary_format:10s} | {avg_time:6.2f} ms/file")

    print(f"\nTotal: {total_time*10:.2f} ms for 600 analyses")
    print(f"Average: {total_time/6*1000:.2f} ms per analysis")


def benchmark_ml_learning():
    print("\n\n=== ML Learning Benchmark ===\n")

    analyzer = Analyzer(use_ml=True)

    png_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452") + b"\x00" * 1000

    print("Teaching 10 examples...")
    start = time.perf_counter()
    for i in range(10):
        analyzer.teach(png_data, "png")
    end = time.perf_counter()

    print(f"Learning time: {(end-start)*1000:.2f} ms for 10 examples")
    print(f"Average: {(end-start)/10*1000:.2f} ms per example")

    print("\nPrediction with ML...")
    start = time.perf_counter()
    for _ in range(100):
        result = analyzer.analyze(png_data)
    end = time.perf_counter()

    print(f"Prediction time: {(end-start)/100*1000:.2f} ms per analysis")
    print(f"Confidence: {result.confidence:.1%}")


def benchmark_large_file():
    print("\n\n=== Large File Handling ===\n")

    import tempfile

    analyzer = Analyzer(use_ml=False)

    sizes = [
        ("1 KB", 1024),
        ("10 KB", 10 * 1024),
        ("100 KB", 100 * 1024),
        ("1 MB", 1024 * 1024),
        ("10 MB", 10 * 1024 * 1024),
    ]

    for name, size in sizes:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(bytes.fromhex("89504E470D0A1A0A"))
            f.write(b"\x00" * (size - 8))
            temp_path = f.name

        start = time.perf_counter()
        result = analyzer.analyze_file(temp_path)
        end = time.perf_counter()

        Path(temp_path).unlink()

        print(f"{name:10s} | {result.primary_format:10s} | {(end-start)*1000:6.2f} ms")


if __name__ == "__main__":
    benchmark_analysis()
    benchmark_ml_learning()
    benchmark_large_file()
