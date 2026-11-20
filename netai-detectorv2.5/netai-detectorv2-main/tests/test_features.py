import numpy as np
import pytest
from netai_detector.features import FEATURE_NAMES, extract_window

class FakeIP:
    src = "192.168.1.10"
    dst = "8.8.8.8"
    proto = 6
    ttl = 64
    ihl = 5

class FakeTCP:
    sport = 51515
    dport = 443
    flags = 2

class FakePacket:
    def __init__(self): self.layers = {"IP": FakeIP(), "TCP": FakeTCP()}
    def haslayer(self, name): return name in self.layers
    def __getitem__(self, name): return self.layers[name]
    def __len__(self): return 100

def test_feature_vector_has_expected_shape_and_finite_values():
    result = extract_window([FakePacket() for _ in range(12)], duration=2)
    assert result.shape == (len(FEATURE_NAMES),)
    assert np.isfinite(result).all()

def test_empty_window_rejected():
    with pytest.raises(ValueError):
        extract_window([])


def test_direction_ratios_are_distinct():
    # FakePacket goes from a private source to a public destination: purely outbound.
    result = extract_window([FakePacket() for _ in range(12)], duration=2)
    named = dict(zip(FEATURE_NAMES, result))
    assert named["outbound_ratio"] == pytest.approx(1.0)
    assert named["inbound_ratio"] == 0.0
    assert named["external_to_external_ratio"] == 0.0
    assert named["packets_per_second"] == pytest.approx(6.0)
