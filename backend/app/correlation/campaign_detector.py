from app.db.neo4j import driver


class CampaignDetector:
    """
    Detect campaign candidate clusters using deterministic BFS traversal
    over the Neo4j property graph.

    Algorithm parameters (from paper, Section 3.5)
    -----------------------------------------------
    d = 2   Maximum traversal depth through infrastructure nodes.
            Depth 1 reaches IOCs connected via a single shared infra node
            (e.g. IOC → IP).  Depth 2 reaches IOCs connected through two
            infrastructure hops (e.g. IOC → IP → ASN).
    k = 3   Minimum cluster size.  Singleton and pair groupings are dropped
            as they are more likely to reflect coincidental co-hosting than
            coordinated campaign activity.

    Reproducibility
    ---------------
    Seed IOC nodes are processed in canonical lexicographic order (ORDER BY
    node.value) so the algorithm always produces the same partition given
    the same graph state.

    Non-overlapping clusters
    ------------------------
    Once an IOC value is assigned to a cluster it is excluded from all
    subsequent traversals.  This simplifies analyst review at the cost of
    potentially under-representing overlapping campaigns (acknowledged as a
    limitation in Section 5.4 of the paper).
    """

    MAX_DEPTH: int = 2  # d — max BFS hops
    MIN_CLUSTER: int = 3  # k — minimum cluster size

    def __init__(self):
        self.driver = driver

    def find_connected_clusters(self) -> list[list[str]]:
        """
        Query the graph for IOC nodes reachable through shared infrastructure
        within MAX_DEPTH hops.  Returns non-overlapping clusters of size ≥ k,
        with seed nodes processed in lexicographic order.
        """
        query = f"""
        MATCH (node)
        WHERE node:URL OR node:Domain OR node:IP

        MATCH (node)-[:HOSTS|RESOLVES_TO_IP|RESOLVES_TO_ASN|HOSTED_BY|REGISTERED_WITH|USES_NS*1..{self.MAX_DEPTH}]-(connected)
        WHERE (connected:URL OR connected:Domain OR connected:IP)
          AND node <> connected

        WITH node, collect(DISTINCT connected.value) + [node.value] AS raw_cluster

        ORDER BY node.value

        WITH node.value AS seed,
             [x IN raw_cluster WHERE x IS NOT NULL] AS raw_cluster
        WHERE size(raw_cluster) >= {self.MIN_CLUSTER}

        RETURN seed, raw_cluster AS cluster
        """

        with self.driver.session() as session:
            result = session.run(query)

            visited: set[str] = set()
            clusters: list[list[str]] = []

            for record in result:
                seed: str = record["seed"]

                # Non-overlapping: skip seeds already assigned to a cluster
                if seed in visited:
                    continue

                # Exclude already-assigned members from this cluster
                raw: list[str] = record["cluster"]
                cluster = sorted(v for v in raw if v not in visited)

                if len(cluster) < self.MIN_CLUSTER:
                    continue

                visited.update(cluster)
                clusters.append(cluster)

        return clusters

    def detect_campaign_candidates(self) -> list[dict]:
        """Return scored campaign candidate dicts (wrapper for pipeline use)."""
        clusters = self.find_connected_clusters()
        return [
            {
                "campaign_id": f"candidate_{i + 1}",
                "indicators": cluster,
                "size": len(cluster),
            }
            for i, cluster in enumerate(clusters)
        ]
