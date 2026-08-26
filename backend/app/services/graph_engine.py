"""
Graph Attribution and Campaign Clustering Engine.

Uses NetworkX for in-memory graph construction, clustering, and querying.
Optional Neo4j integration when configured.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from app.config import settings

logger = logging.getLogger(__name__)

class GraphEngine:
    """Builds and queries relationship graphs for threat campaigns."""

    def __init__(self) -> None:
        self.nx_graph = nx.DiGraph()
        self.neo4j_driver = None

        if settings.neo4j_enabled:
            try:
                from neo4j import GraphDatabase
                self.neo4j_driver = GraphDatabase.driver(
                    settings.neo4j_uri, 
                    auth=(settings.neo4j_user, settings.neo4j_password)
                )
                logger.info("GraphEngine: Connected to Neo4j.")
            except Exception as e:
                logger.error("GraphEngine: Failed to connect to Neo4j: %s. Falling back to NetworkX.", e)

    def add_email_case(self, case_data: dict[str, Any]) -> None:
        """
        Add nodes and relationships for an analyzed email.
        case_data expects: case_id, from_address, from_domain, sender_ip, asn, subject, risk_category
        """
        case_id = case_data.get("case_id")
        if not case_id:
            return

        # NetworkX insertion
        self.nx_graph.add_node(case_id, type="Email", label=case_data.get("subject", "No Subject"), category=case_data.get("risk_category"))
        
        from_addr = case_data.get("from_address")
        if from_addr:
            self.nx_graph.add_node(from_addr, type="Sender", label=from_addr)
            self.nx_graph.add_edge(from_addr, case_id, type="SENT")

        from_domain = case_data.get("from_domain")
        if from_domain:
            self.nx_graph.add_node(from_domain, type="Domain", label=from_domain)
            if from_addr:
                self.nx_graph.add_edge(from_addr, from_domain, type="USES_DOMAIN")

        sender_ip = case_data.get("sender_ip")
        if sender_ip:
            self.nx_graph.add_node(sender_ip, type="IP", label=sender_ip)
            self.nx_graph.add_edge(case_id, sender_ip, type="ORIGINATED_FROM")

        asn = case_data.get("asn")
        if asn and sender_ip:
            self.nx_graph.add_node(asn, type="ASN", label=asn)
            self.nx_graph.add_edge(sender_ip, asn, type="RESOLVES_TO")

        # Optional Neo4j insertion
        if self.neo4j_driver:
            self._add_to_neo4j(case_data)

    def _add_to_neo4j(self, case_data: dict[str, Any]) -> None:
        """Add graph data to Neo4j database."""
        query = """
        MERGE (e:Email {id: $case_id})
        SET e.subject = $subject, e.category = $risk_category
        WITH e
        """
        params = {
            "case_id": case_data.get("case_id"),
            "subject": case_data.get("subject", ""),
            "risk_category": case_data.get("risk_category", ""),
        }
        
        parts = [query]
        
        if case_data.get("from_address"):
            parts.append("""
            MERGE (s:Sender {id: $from_address})
            MERGE (s)-[:SENT]->(e)
            """)
            params["from_address"] = case_data["from_address"]
            
            if case_data.get("from_domain"):
                parts.append("""
                MERGE (d:Domain {id: $from_domain})
                MERGE (s)-[:USES_DOMAIN]->(d)
                """)
                params["from_domain"] = case_data["from_domain"]

        if case_data.get("sender_ip"):
            parts.append("""
            MERGE (ip:IP {id: $sender_ip})
            MERGE (e)-[:ORIGINATED_FROM]->(ip)
            """)
            params["sender_ip"] = case_data["sender_ip"]
            
            if case_data.get("asn"):
                parts.append("""
                MERGE (a:ASN {id: $asn})
                MERGE (ip)-[:RESOLVES_TO]->(a)
                """)
                params["asn"] = case_data["asn"]

        final_query = "\n".join(parts)
        
        try:
            with self.neo4j_driver.session() as session:
                session.run(final_query, **params)
        except Exception as e:
            logger.error("Failed to write to Neo4j: %s", e)

    def get_case_graph(self, case_id: str) -> dict[str, list[dict[str, Any]]]:
        """Return graph data (nodes/edges) for a specific case."""
        if case_id not in self.nx_graph:
            return {"nodes": [], "edges": []}

        # Get connected component / subgraph
        undirected = self.nx_graph.to_undirected()
        
        try:
            nodes_in_subgraph = nx.node_connected_component(undirected, case_id)
            subgraph = self.nx_graph.subgraph(nodes_in_subgraph)
        except KeyError:
            subgraph = self.nx_graph.subgraph([case_id])

        return self._format_graph(subgraph)

    def get_full_graph(self) -> dict[str, list[dict[str, Any]]]:
        """Return the entire graph for visualization."""
        return self._format_graph(self.nx_graph)
        
    def _format_graph(self, graph: nx.DiGraph) -> dict[str, list[dict[str, Any]]]:
        """Format a NetworkX graph into node/edge dict for frontend visualization."""
        nodes = []
        for n, data in graph.nodes(data=True):
            node_data = {"id": n, "label": data.get("label", str(n)), "group": data.get("type", "Unknown")}
            if "category" in data:
                node_data["category"] = data["category"]
            nodes.append(node_data)
            
        edges = []
        for u, v, data in graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "label": data.get("type", ""),
            })
            
        return {"nodes": nodes, "edges": edges}

    def close(self):
        if self.neo4j_driver:
            self.neo4j_driver.close()


# Singleton instance
graph_engine = GraphEngine()
