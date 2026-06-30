from app.correlation.confidence_scorer import CampaignConfidenceScorer
from app.correlation.infrastructure_engine import InfrastructureEngine
from app.ingestion.enrichment.models.campaign_models import Campaign
from app.services.timeline_service import TimelineService
from sqlalchemy.orm import Session


class CampaignEngine:
    """
    Convert infrastructure clusters into persistent, confidence-scored campaigns.

    Clustering is performed by InfrastructureEngine (Jaccard fingerprint
    similarity).  Confidence scoring uses CampaignConfidenceScorer which
    implements the weighted additive formula described in the paper:

        score(C) = α·N(C) + β·D(C) + γ·R(C) + δ·E(C)

    The same fingerprint dict is reused for both clustering and scoring so
    that R(C) and E(C) are computed from the same enrichment snapshot.
    """

    def __init__(self):
        self.infrastructure_engine = InfrastructureEngine()
        self.scorer = CampaignConfidenceScorer()
        self.timeline = TimelineService()

    def generate_campaign_id(self, cluster: list[str]) -> str:
        """Deterministic campaign ID derived from sorted cluster membership."""
        return "campaign_" + str(abs(hash("|".join(sorted(cluster)))) % 10**10)

    def detect_campaigns(self, db: Session) -> list[dict]:
        """
        Run the full clustering → scoring → persistence pipeline.

        Returns a list of scored campaign dicts (one per cluster), including
        both newly created and pre-existing campaigns.
        """
        # Build enrichment fingerprints once; reused for clustering and scoring
        fingerprints = self.infrastructure_engine.build_fingerprints(db)
        clusters = self.infrastructure_engine.detect_clusters(db)

        # Assemble raw campaign dicts
        raw_campaigns = [
            {
                "campaign_id": self.generate_campaign_id(cluster),
                "indicators": cluster,
                "size": len(cluster),
            }
            for cluster in clusters
        ]

        # Score all campaigns together so N(C) is normalised across the full batch
        scored_campaigns = self.scorer.score_campaigns(raw_campaigns, fingerprints=fingerprints)

        result = []

        for campaign in scored_campaigns:
            campaign_id = campaign["campaign_id"]

            existing = db.query(Campaign).filter(Campaign.campaign_id == campaign_id).first()

            if existing:
                result.append(campaign)
                continue

            record = Campaign(
                campaign_id=campaign_id,
                indicator_count=campaign["size"],
                confidence=campaign["confidence"],
                strength=campaign["strength"],
            )

            db.add(record)

            self.timeline.record_event(
                db=db,
                event_type="campaign_created",
                event_value=campaign_id,
                campaign_id=campaign_id,
                source="campaign_engine",
            )

            result.append(campaign)

        db.commit()
        return result
