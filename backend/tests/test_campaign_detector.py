from unittest.mock import MagicMock

from app.correlation.campaign_detector import CampaignDetector


def test_campaign_detection_returns_clusters():
    detector = CampaignDetector()

    mock_session = MagicMock()
    mock_driver = MagicMock()

    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_session.run.return_value = [
        {"seed": "evil.com", "cluster": ["evil.com", "1.1.1.1", "http://evil.com/login"]}
    ]

    detector.driver = mock_driver

    clusters = detector.detect_campaign_candidates()

    assert len(clusters) == 1
    assert clusters[0]["size"] == 3
