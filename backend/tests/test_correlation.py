"""Claims: alerts sharing a process-ancestry chain grouped into one
fidelity-scored incident, and the resulting reduction in analyst-facing
items."""
from app.correlation import PrimaryCorrelationEngine, analyst_facing_reduction
from app.correlation_fixtures import (
    CORRELATION_AS_OF,
    NUM_CHAINED_INCIDENTS,
    NUM_STANDALONE,
    build_correlation_corpus,
)
from app.engine import PrimaryEngine
from app.generators import known_good_hashes


def _evaluate_corpus():
    events, calendar, chained_incidents, standalone = build_correlation_corpus()
    hashes = known_good_hashes()
    alerts = PrimaryEngine().evaluate(events, calendar, hashes, as_of=CORRELATION_AS_OF)
    return alerts, chained_incidents, standalone


def test_chained_incidents_each_produce_eight_alerts_before_correlation():
    alerts, chained_incidents, standalone = _evaluate_corpus()
    # 15 chains * 8 alerts + 18 standalone = 138 raw alerts, before grouping.
    assert len(alerts) == NUM_CHAINED_INCIDENTS * 8 + NUM_STANDALONE


def test_each_chain_collapses_to_exactly_one_incident():
    alerts, chained_incidents, standalone = _evaluate_corpus()
    incidents = PrimaryCorrelationEngine().group(alerts)

    multi_alert_incidents = [inc for inc in incidents if inc.alert_count() > 1]
    assert len(multi_alert_incidents) == NUM_CHAINED_INCIDENTS
    for inc in multi_alert_incidents:
        assert inc.alert_count() == 8
        assert set(inc.rule_ids) == {
            "ENG_LAPTOP_OFF_WINDOW", "NEW_EXEC_CONTROL_HOST", "UNEXPECTED_SERVICE_LOGON",
            "ISOLATED_HOST_OUTBOUND", "REPEATED_FAILED_AUTH_HMI", "CONTROL_HOST_REBOOT_OFF_WINDOW",
        }


def test_standalone_alerts_never_false_grouped():
    alerts, chained_incidents, standalone = _evaluate_corpus()
    incidents = PrimaryCorrelationEngine().group(alerts)

    single_alert_incidents = [inc for inc in incidents if inc.alert_count() == 1]
    assert len(single_alert_incidents) == NUM_STANDALONE


def test_fidelity_score_rewards_diverse_multi_host_chains():
    alerts, chained_incidents, standalone = _evaluate_corpus()
    incidents = PrimaryCorrelationEngine().group(alerts)

    chain_scores = [inc.fidelity_score for inc in incidents if inc.alert_count() > 1]
    single_scores = [inc.fidelity_score for inc in incidents if inc.alert_count() == 1]
    assert min(chain_scores) > max(single_scores)


def test_analyst_facing_reduction_measured_not_targeted():
    alerts, chained_incidents, standalone = _evaluate_corpus()
    result = analyst_facing_reduction(alerts)
    assert result["alerts_before"] == NUM_CHAINED_INCIDENTS * 8 + NUM_STANDALONE
    assert result["incidents_after"] == NUM_CHAINED_INCIDENTS + NUM_STANDALONE
    # Recorded in README/build_report.json as measured, not asserted to a
    # specific target here: this test only pins the mechanism (before/after
    # counts), not the headline percentage.
    assert 0.0 < result["reduction_pct"] < 100.0
