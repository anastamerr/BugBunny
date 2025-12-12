from unittest.mock import MagicMock


def test_cluster_by_root_cause_groups_correctly():
    from src.services.correlation.bug_clusterer import BugClusterer

    db = MagicMock()
    clusterer = BugClusterer(db)

    b1 = MagicMock(correlated_incident_id="i1")
    b2 = MagicMock(correlated_incident_id="i1")
    b3 = MagicMock(correlated_incident_id=None)

    clusters = clusterer.cluster_by_root_cause([b1, b2, b3])
    assert "i1" in clusters
    assert "uncorrelated" in clusters
    assert len(clusters["i1"]) == 2


def test_propagate_resolution_updates_bugs():
    from src.services.correlation.bug_clusterer import BugClusterer

    bug1 = MagicMock()
    bug2 = MagicMock()
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = [bug1, bug2]

    clusterer = BugClusterer(db)
    count = clusterer.propagate_resolution("i1", "fixed schema")

    assert count == 2
    assert bug1.status == "resolved"
    assert "fixed schema" in bug1.resolution_notes
    db.commit.assert_called_once()

