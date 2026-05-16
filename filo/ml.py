import pickle
import logging
import zlib
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import math

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    offset: int
    pattern: bytes
    format: str
    weight: float = 1.0


@dataclass
class LearningExample:
    file_hash: str
    patterns: List[PatternMatch] = field(default_factory=list)
    correct_format: str = ""
    file_size: int = 0
    entropy: float = 0.0
    incorrect_formats: List[str] = field(default_factory=list)
    features: Dict[str, float] = field(default_factory=dict)
    ngram_profile: Dict[bytes, float] = field(default_factory=dict)


class MLDetector:
    def __init__(self, model_path: Optional[Path] = None) -> None:
        if model_path is None:
            model_path = Path.home() / ".filo" / "learned_patterns.pkl"

        self.model_path = Path(model_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

        self.pattern_weights: Dict[Tuple[int, bytes, str], float] = {}
        self.negative_patterns: Dict[Tuple[int, bytes, str], float] = {}
        self.format_confidence_boost: Dict[str, float] = defaultdict(float)
        self.format_stats: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {"count": 0, "avg_entropy": 0.0, "avg_size": 0.0}
        )
        self.format_features: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.format_ngrams: Dict[str, Dict[bytes, float]] = defaultdict(dict)

        self.load_model()

    def load_model(self) -> None:
        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self.pattern_weights = data.get("patterns", {})
                    self.negative_patterns = data.get("negative_patterns", {})
                    self.format_confidence_boost = defaultdict(
                        float, data.get("confidence_boost", {})
                    )
                    self.format_stats = defaultdict(
                        lambda: {"count": 0, "avg_entropy": 0.0, "avg_size": 0.0},
                        data.get("stats", {}),
                    )
                    self.format_features = defaultdict(dict, data.get("features", {}))
                    self.format_ngrams = defaultdict(dict, data.get("ngrams", {}))
                logger.info(
                    f"Loaded ML model with {len(self.pattern_weights)} patterns, {len(self.format_ngrams)} n-gram profiles"
                )
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")

    def save_model(self) -> None:
        try:
            with open(self.model_path, "wb") as f:
                pickle.dump(
                    {
                        "patterns": dict(self.pattern_weights),
                        "negative_patterns": dict(self.negative_patterns),
                        "confidence_boost": dict(self.format_confidence_boost),
                        "stats": dict(self.format_stats),
                        "features": dict(self.format_features),
                        "ngrams": dict(self.format_ngrams),
                    },
                    f,
                )
            logger.info(f"Saved ML model to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save ML model: {e}")

    def learn(self, example: LearningExample) -> None:
        for pattern in example.patterns:
            key = (pattern.offset, pattern.pattern, example.correct_format)
            current_weight = self.pattern_weights.get(key, 0.0)
            self.pattern_weights[key] = min(1.0, current_weight + 0.15)

        for incorrect_fmt in example.incorrect_formats:
            for pattern in example.patterns:
                neg_key = (pattern.offset, pattern.pattern, incorrect_fmt)
                self.negative_patterns[neg_key] = self.negative_patterns.get(neg_key, 0.0) + 0.1

        self.format_confidence_boost[example.correct_format] += 0.05

        stats = self.format_stats[example.correct_format]
        count = stats["count"]
        stats["avg_entropy"] = (stats["avg_entropy"] * count + example.entropy) / (count + 1)
        stats["avg_size"] = (stats["avg_size"] * count + example.file_size) / (count + 1)
        stats["count"] = count + 1

        # Store rich features
        if example.features:
            fmt_features = self.format_features[example.correct_format]
            for feature_name, value in example.features.items():
                current_avg = fmt_features.get(feature_name, 0.0)
                fmt_features[feature_name] = (current_avg * count + value) / (count + 1)

        # Store n-gram profile
        if example.ngram_profile:
            self.format_ngrams[example.correct_format] = example.ngram_profile

        self.save_model()

    def predict(self, data: bytes, entropy: float, file_size: int) -> List[Tuple[str, float]]:
        if not self.pattern_weights and not self.format_ngrams:
            return []

        format_scores: Dict[str, float] = defaultdict(float)

        scan_length = min(8192, len(data))

        # Pattern matching
        for (offset, pattern, fmt), weight in self.pattern_weights.items():
            if offset >= scan_length:
                continue

            end_offset = offset + len(pattern)
            if end_offset <= len(data) and data[offset:end_offset] == pattern:
                format_scores[fmt] += weight

                neg_key = (offset, pattern, fmt)
                if neg_key in self.negative_patterns:
                    format_scores[fmt] -= self.negative_patterns[neg_key] * 0.5

        # Statistical features matching
        for fmt, stats in self.format_stats.items():
            if stats["count"] < 3:
                continue

            entropy_diff = abs(entropy - stats["avg_entropy"])
            size_ratio = min(file_size, stats["avg_size"]) / max(file_size, stats["avg_size"], 1)

            if entropy_diff < 2.0:
                format_scores[fmt] += 0.2
            if size_ratio > 0.5:
                format_scores[fmt] += 0.1

        # Rich features matching
        if self.format_features:
            file_features = self.extract_features(data)
            for fmt, fmt_features in self.format_features.items():
                feature_similarity = self._compare_features(file_features, fmt_features)
                format_scores[fmt] += feature_similarity * 0.3

        # N-gram profile matching
        if self.format_ngrams:
            file_ngrams = self.build_ngram_profile(data, n=3)
            for fmt, fmt_ngrams in self.format_ngrams.items():
                ngram_similarity = self.ngram_similarity(file_ngrams, fmt_ngrams)
                format_scores[fmt] += ngram_similarity * 0.4

        for fmt in format_scores:
            format_scores[fmt] += self.format_confidence_boost.get(fmt, 0.0)

        results = sorted(format_scores.items(), key=lambda x: x[1], reverse=True)

        if results:
            max_score = results[0][1]
            if max_score > 0:
                results = [(fmt, min(1.0, score / max_score)) for fmt, score in results]

        return results[:3]

    def extract_patterns(self, data: bytes, max_patterns: int = 10) -> List[bytes]:
        patterns = []

        for size in [4, 8, 16]:
            for offset in range(0, min(1024, len(data) - size), size):
                pattern = data[offset : offset + size]
                if len(set(pattern)) > 1:
                    patterns.append(pattern)

        return patterns[:max_patterns]

    def extract_discriminative_patterns(
        self, data: bytes, max_patterns: int = 20
    ) -> List[PatternMatch]:
        """Extract discriminative patterns automatically from file data."""
        patterns = []

        # Header patterns (first 32 bytes in chunks)
        if len(data) >= 32:
            for size in [4, 8, 12, 16]:
                if len(data) >= size:
                    patterns.append(PatternMatch(0, data[:size], "", 1.0))

        # Footer patterns (last 16 bytes)
        if len(data) >= 64:
            patterns.append(PatternMatch(len(data) - 16, data[-16:], "", 0.7))

        # Extract frequent n-grams (discriminative sequences)
        scan_len = min(8192, len(data))
        ngram_sizes = [4, 8, 12]

        for n in ngram_sizes:
            if len(data) < n:
                continue

            ngrams = Counter()
            for i in range(scan_len - n):
                ngram = data[i : i + n]
                # Skip uniform patterns (all same byte)
                if len(set(ngram)) > 2:
                    ngrams[ngram] += 1

            # Keep most frequent ngrams that appear multiple times
            for ngram, count in ngrams.most_common(5):
                if count >= 2:
                    offset = data.find(ngram)
                    weight = min(0.9, 0.4 + (count * 0.1))
                    patterns.append(PatternMatch(offset, ngram, "", weight))

        return patterns[:max_patterns]

    def extract_features(self, data: bytes) -> Dict[str, float]:
        """Extract comprehensive statistical features from file data."""
        features = {}
        scan_len = min(8192, len(data))
        sample = data[:scan_len]

        if not sample:
            return features

        # Byte frequency distribution
        byte_counts = [0] * 256
        for byte in sample:
            byte_counts[byte] += 1

        # Basic statistics
        features["null_byte_ratio"] = byte_counts[0] / len(sample)
        features["printable_ratio"] = sum(1 for b in sample if 32 <= b < 127) / len(sample)
        features["high_byte_ratio"] = sum(1 for b in sample if b >= 128) / len(sample)

        # Byte distribution variance (measure of randomness)
        mean_count = len(sample) / 256
        variance = sum((count - mean_count) ** 2 for count in byte_counts) / 256
        features["byte_variance"] = variance

        # Compression ratio (compressed formats won't compress further)
        try:
            compressed = zlib.compress(sample, level=6)
            features["compression_ratio"] = len(compressed) / len(sample)
        except Exception:
            features["compression_ratio"] = 1.0

        # Longest repeating byte sequence
        features["max_repeat_length"] = self._find_longest_repeat(sample)

        # ASCII/text heuristic
        features["likely_text"] = 1.0 if features["printable_ratio"] > 0.7 else 0.0

        # Entropy calculation (if not already provided)
        if len(sample) > 0:
            byte_probs = [count / len(sample) for count in byte_counts if count > 0]
            features["entropy"] = -sum(p * math.log2(p) for p in byte_probs if p > 0)

        return features

    def _find_longest_repeat(self, data: bytes, max_len: int = 256) -> int:
        """Find the longest sequence of repeating bytes."""
        if not data:
            return 0

        max_repeat = 0
        current_repeat = 1

        for i in range(1, min(len(data), 1024)):
            if data[i] == data[i - 1]:
                current_repeat += 1
                max_repeat = max(max_repeat, current_repeat)
            else:
                current_repeat = 1

        return min(max_repeat, max_len)

    def build_ngram_profile(self, data: bytes, n: int = 3) -> Dict[bytes, float]:
        """Build normalized n-gram frequency profile."""
        ngrams = Counter()
        scan_len = min(8192, len(data))

        if len(data) < n:
            return {}

        for i in range(scan_len - n):
            ngrams[data[i : i + n]] += 1

        total = sum(ngrams.values())
        if total == 0:
            return {}

        # Keep top 100 most frequent n-grams
        return {ng: count / total for ng, count in ngrams.most_common(100)}

    def ngram_similarity(self, profile1: Dict[bytes, float], profile2: Dict[bytes, float]) -> float:
        """Calculate cosine similarity between n-gram profiles."""
        if not profile1 or not profile2:
            return 0.0

        common_keys = set(profile1.keys()) & set(profile2.keys())
        if not common_keys:
            return 0.0

        dot_product = sum(profile1[k] * profile2[k] for k in common_keys)

        mag1 = math.sqrt(sum(v * v for v in profile1.values()))
        mag2 = math.sqrt(sum(v * v for v in profile2.values()))

        if mag1 == 0 or mag2 == 0:
            return 0.0

        return dot_product / (mag1 * mag2)

    def _compare_features(self, features1: Dict[str, float], features2: Dict[str, float]) -> float:
        """Compare feature dictionaries and return similarity score."""
        if not features1 or not features2:
            return 0.0

        common_keys = set(features1.keys()) & set(features2.keys())
        if not common_keys:
            return 0.0

        differences = []
        for key in common_keys:
            val1 = features1[key]
            val2 = features2[key]

            # Normalize difference based on the scale
            if key in [
                "compression_ratio",
                "printable_ratio",
                "null_byte_ratio",
                "high_byte_ratio",
                "likely_text",
            ]:
                # These are 0-1 range
                diff = abs(val1 - val2)
            elif key == "entropy":
                # 0-8 range
                diff = abs(val1 - val2) / 8.0
            elif key == "byte_variance":
                # Normalize by max expected variance
                diff = abs(val1 - val2) / 10000.0
            elif key == "max_repeat_length":
                # Normalize by 256
                diff = abs(val1 - val2) / 256.0
            else:
                diff = abs(val1 - val2)

            differences.append(diff)

        # Average similarity (1 - average difference)
        avg_diff = sum(differences) / len(differences) if differences else 1.0
        return max(0.0, 1.0 - avg_diff)
