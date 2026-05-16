from filo.ml import MLDetector, LearningExample, PatternMatch


def test_ml_detector_initialization(tmp_path):
    model_path = tmp_path / "test_model.pkl"
    detector = MLDetector(model_path)

    assert detector.model_path == model_path
    assert len(detector.pattern_weights) == 0


def test_learn_and_predict(tmp_path):
    model_path = tmp_path / "test_model.pkl"
    detector = MLDetector(model_path)

    png_data = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 100

    example = LearningExample(
        file_hash="test123",
        patterns=[
            PatternMatch(
                offset=0, pattern=bytes.fromhex("89504E470D0A1A0A"), format="png", weight=1.0
            )
        ],
        correct_format="png",
        file_size=108,
        entropy=0.5,
    )

    detector.learn(example)

    predictions = detector.predict(png_data, 0.5, 108)

    assert len(predictions) > 0
    assert predictions[0][0] == "png"


def test_model_persistence(tmp_path):
    model_path = tmp_path / "test_model.pkl"

    detector1 = MLDetector(model_path)
    example = LearningExample(
        file_hash="test",
        patterns=[PatternMatch(0, b"\x89PNG", "png")],
        correct_format="png",
        file_size=100,
        entropy=0.5,
    )
    detector1.learn(example)

    detector2 = MLDetector(model_path)
    assert len(detector2.pattern_weights) > 0


def test_extract_patterns():
    detector = MLDetector()
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

    patterns = detector.extract_patterns(data)
    assert len(patterns) > 0
    assert isinstance(patterns[0], bytes)
