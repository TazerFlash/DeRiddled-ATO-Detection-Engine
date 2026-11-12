"""Replay validation windows through state.py and assert every main-model feature equals the offline feature tables."""
import pytest

from deriddled.config import load_config, path
from deriddled.parity import run

cfg = load_config()["data"]
pytestmark = pytest.mark.skipif(
    not (path(cfg["features_dir"]).exists() and path(cfg["likelihood_dir"]).exists() and path(cfg["reputation_dir"]).exists()),
    reason="full feature, likelihood and reputation tables not built")


@pytest.mark.parametrize("start,hours", [("2020-09-15 11:00:00", 3.0), ("2020-08-03 19:00:00", 1.0)])
def test_online_features_match_offline(start, hours):
    report = run(start, hours)
    assert report.rows.min() > 0
    bad = report[report.mismatches > 0]
    assert bad.empty, "\n" + bad.to_string(index=False)
