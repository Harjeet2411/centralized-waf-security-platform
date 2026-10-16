import pytest

from common import scoring


def test_waf_weights_sum_to_one():
    assert sum(scoring.WAF_WEIGHTS.values()) == pytest.approx(1.0)


def test_perfect_and_worst_webacl():
    best = dict.fromkeys(scoring.WAF_WEIGHTS, 100.0)
    worst = dict.fromkeys(scoring.WAF_WEIGHTS, 0.0)
    assert scoring.waf_score(best) == 100.0 and scoring.waf_score(worst) == 0.0
    no_logging = {**best, "logging": 0.0}
    assert scoring.waf_score(no_logging) == 95.0  # logging alone can never make a WebACL "critical"


def test_dimensions():
    assert scoring.d_coverage(3, 4) == 75.0 and scoring.d_coverage(0, 0) == 100.0
    assert scoring.d_blocking(8, 10) == 80.0 and scoring.d_blocking(0, 0) == 100.0
    assert scoring.d_malicious_allowed(0) == 100.0 and scoring.d_malicious_allowed(5) == 50.0
    assert scoring.d_count_exposure([{"managed_group_name": None, "age_days": 3}]) == 100.0  # inside tuning window
    assert scoring.d_count_exposure([
        {"managed_group_name": "AWSManagedRulesSQLiRuleSet", "age_days": 30},
        {"managed_group_name": None, "age_days": 30},
    ]) == 35.0
    assert scoring.d_drift({"CRITICAL": 1, "HIGH": 1, "LOW": 2}) == 30.0
    assert scoring.d_drift({"CRITICAL": 3}) == 0.0
    assert scoring.d_managed_versions(["CURRENT", "OUTDATED", "UNKNOWN"]) == 50.0
    assert scoring.d_managed_versions([]) == 100.0


@pytest.mark.parametrize(("levels", "expected"), [
    (["full", "full"], "FULL"), (["full", "sampled"], "PARTIAL"), (["sampled", "metrics"], "SAMPLED"),
    (["metrics"], "NONE"), ([], "NONE"),
])
def test_account_confidence(levels, expected):
    assert scoring.account_confidence(levels) == expected


def test_entity_threat_and_risk():
    ti = scoring.t_ti([{"score": 98, "confidence": 98}, {"score": 0, "confidence": 30}])
    assert ti == pytest.approx(98 * 98 / 128)
    t = scoring.threat_score(100, 100, 100, 100)
    assert t == 100.0
    assert scoring.threat_score(80, 40, 50, 0) == pytest.approx(0.35 * 80 + 0.25 * 40 + 0.20 * 50)
    assert scoring.final_risk(90, 95) == 92
    assert scoring.risk_level(92, 0) == "CRITICAL"
    assert scoring.risk_level(50, 3) == "CRITICAL"  # any malicious-allowed traffic is critical
    assert [scoring.risk_level(r, 0) for r in (84, 70, 69, 40, 39)] == ["HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"]


def test_business_impact_and_classification():
    assert scoring.business_impact("development", False) == 20.0
    assert scoring.business_impact("development", True) == 90.0
    assert scoring.business_impact("production", True) == 90.0
    assert scoring.classification(80, allow_listed=True) == "MALICIOUS"
    assert scoring.classification(50, allow_listed=True) == "LEGITIMATE"
    assert scoring.classification(50, allow_listed=False) == "SUSPICIOUS"


def test_component_scores_bounded():
    assert scoring.t_waf(10, 10, ["RCE"], 500) == 100.0
    assert scoring.t_ja4(0, 0, 9) == 0.0 and scoring.t_ja4(9, 10, 6) == 100.0
    assert scoring.confidence(10**9, 5, True) == 100.0
