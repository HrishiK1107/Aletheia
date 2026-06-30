from collections import Counter


class CampaignConfidenceScorer:
    """
    Deterministic scoring engine for campaign clusters.

    Implements the weighted additive formula from the paper:

        score(C) = α·N(C) + β·D(C) + γ·R(C) + δ·E(C)

    Components
    ----------
    N(C)  Normalised cluster size: IOC count / largest cluster in this run.
    D(C)  Indicator type diversity: distinct IOC types observed / 3 (max), capped at 1.0.
    R(C)  Infrastructure reuse ratio: shared infra features / IOC count, capped at 1.0.
    E(C)  Enrichment completeness: fraction of cluster members with ≥1 attribute resolved.

    Weights: α=0.30, β=0.30, γ=0.20, δ=0.20  (sum = 1.0)

    Confidence bands
    ----------------
    High   > 70
    Medium  40–70
    Low    < 40
    """

    ALPHA = 0.30  # cluster size
    BETA = 0.30  # type diversity
    GAMMA = 0.20  # infrastructure reuse
    DELTA = 0.20  # enrichment completeness

    def __init__(self):
        pass

    # ------------------------------------------------------------------
    # Component helpers
    # ------------------------------------------------------------------

    def _normalised_size(self, size: int, max_cluster_size: int) -> float:
        if max_cluster_size <= 0:
            return 0.0
        return min(size / max_cluster_size, 1.0)

    def _type_diversity(self, indicators: list) -> float:
        """D(C): distinct IOC types / 3, capped at 1.0."""
        types: set = set()
        for value in indicators:
            if value.startswith("http"):
                types.add("url")
            elif value.count(".") == 3 and all(part.isdigit() for part in value.split(".")):
                types.add("ip")
            elif "." in value:
                types.add("domain")
            else:
                types.add("hash")
        return min(len(types) / 3.0, 1.0)

    def _infrastructure_reuse_ratio(self, indicators: list, fingerprints: dict) -> float:
        """
        R(C): number of infrastructure features shared by ≥2 IOCs,
        divided by cluster size, capped at 1.0.
        """
        if not fingerprints or not indicators:
            return 0.0

        feature_counts: Counter = Counter()
        for ind in indicators:
            for feat in fingerprints.get(ind, set()):
                feature_counts[feat] += 1

        shared = sum(1 for count in feature_counts.values() if count >= 2)
        return min(shared / len(indicators), 1.0)

    def _enrichment_completeness(self, indicators: list, fingerprints: dict) -> float:
        """E(C): fraction of cluster members with ≥1 enrichment attribute resolved."""
        if not fingerprints or not indicators:
            return 0.0
        enriched = sum(1 for ind in indicators if fingerprints.get(ind))
        return enriched / len(indicators)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def compute_score(
        self,
        campaign: dict,
        fingerprints: dict | None = None,
        max_cluster_size: int | None = None,
    ) -> int:
        """
        Compute a 0–100 confidence score for a campaign cluster.

        Parameters
        ----------
        campaign : dict
            Must contain keys ``indicators`` (list[str]) and ``size`` (int).
        fingerprints : dict, optional
            Mapping of indicator value → set of infrastructure feature strings,
            as produced by ``InfrastructureEngine.build_fingerprints()``.
            Required for non-zero R(C) and E(C) components.
        max_cluster_size : int, optional
            Largest cluster observed in this collection run, used to normalise
            N(C).  Defaults to the campaign's own size when not supplied.
        """
        indicators = campaign["indicators"]
        size = campaign["size"]

        effective_max = max_cluster_size if (max_cluster_size and max_cluster_size > 0) else size
        fp = fingerprints or {}

        N = self._normalised_size(size, effective_max)
        D = self._type_diversity(indicators)
        R = self._infrastructure_reuse_ratio(indicators, fp)
        E = self._enrichment_completeness(indicators, fp)

        raw = self.ALPHA * N + self.BETA * D + self.GAMMA * R + self.DELTA * E
        return round(raw * 100)

    def classify_confidence(self, score: int) -> str:
        """Map numeric score to a confidence band."""
        if score > 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def score_campaign(
        self,
        campaign: dict,
        fingerprints: dict | None = None,
        max_cluster_size: int | None = None,
    ) -> dict:
        """Return campaign dict extended with ``confidence`` and ``strength`` keys."""
        score = self.compute_score(campaign, fingerprints, max_cluster_size)
        return {
            **campaign,
            "confidence": score,
            "strength": self.classify_confidence(score),
        }

    def score_campaigns(
        self,
        campaigns: list,
        fingerprints: dict | None = None,
    ) -> list:
        """
        Score a list of campaign candidates.

        Derives ``max_cluster_size`` from the batch so N(C) is normalised
        consistently across all clusters in the same collection cycle.
        """
        if not campaigns:
            return []
        max_size = max(c["size"] for c in campaigns)
        return [self.score_campaign(c, fingerprints, max_size) for c in campaigns]
