from collections import deque
import json
import os
import threading
import networkx as nx

DB_FILE = "graph_state.json"
MAX_NODES = 2500

file_lock = threading.Lock()
graph_lock = threading.RLock()


class FraudGraphEngine:

    def __init__(self, max_nodes: int = MAX_NODES):
        self.graph = nx.DiGraph()
        self.max_nodes = max_nodes
        self.node_history = deque()
        self.load_from_disk()

    def _track_node(self, node_id: str, node_type: str):
        if not self.graph.has_node(node_id):
            self.graph.add_node(node_id, type=node_type, tx_count=1)
            self.node_history.append(node_id)
            self._evict_if_needed()
        else:
            self.graph.nodes[node_id]["tx_count"] = (
                self.graph.nodes[node_id].get("tx_count", 0) + 1
            )

    def _evict_if_needed(self):
        while len(self.graph.nodes) > self.max_nodes and self.node_history:
            oldest = self.node_history.popleft()
            if self.graph.has_node(oldest):
                self.graph.remove_node(oldest)

    def save_to_disk(self):
        with graph_lock:
            data = nx.node_link_data(self.graph)
        with file_lock:
            try:
                with open(DB_FILE, "w") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print(f"[FraudEngine] Disk save warning: {e}")

    def load_from_disk(self):
        with file_lock:
            if os.path.exists(DB_FILE):
                try:
                    with open(DB_FILE, "r") as f:
                        data = json.load(f)
                    with graph_lock:
                        self.graph = nx.node_link_graph(data)
                        self.node_history = deque(self.graph.nodes)
                except Exception as e:
                    print(f"[FraudEngine] Resetting initial state: {e}")

    def ingest_transaction(
        self,
        account_id: str,
        device_hash: str,
        ip_subnet: str,
        payout_wallet_id: str,
        source_wallet_id: str | None = None,
        latent_peers: list[dict] | None = None,
    ):
        with graph_lock:
            self._track_node(account_id, "account")
            self._track_node(device_hash, "device")
            self._track_node(ip_subnet, "ip")
            self._track_node(payout_wallet_id, "wallet")

            if source_wallet_id:
                self._track_node(source_wallet_id, "wallet")
                self.graph.add_edge(source_wallet_id, account_id, relation="EXPLICIT")

            self.graph.add_edge(account_id, device_hash, relation="EXPLICIT")
            self.graph.add_edge(account_id, ip_subnet, relation="EXPLICIT")
            self.graph.add_edge(account_id, payout_wallet_id, relation="EXPLICIT")

            if latent_peers:
                for p in latent_peers[:6]:
                    peer_id = p["account_id"]
                    self._track_node(peer_id, "account")
                    self.graph.add_edge(
                        account_id,
                        peer_id,
                        relation="ML_LATENT_COHORT",
                        similarity=p["similarity"],
                    )

    def analyze_cluster_risk(
        self,
        account_id: str,
        device_hash: str,
        payout_wallet_id: str,
        config: dict,
        source_wallet_id: str | None = None,
    ):
        cluster_flagged = False
        reasons = []
        score_boost = 0.0

        with graph_lock:
            if self.graph.has_node(device_hash):
                linked_accounts = [
                    n
                    for n in self.graph.predecessors(device_hash)
                    if self.graph.nodes[n].get("type") == "account"
                ]
                if len(linked_accounts) >= 1 and account_id not in linked_accounts:
                    cluster_flagged = True
                    score_boost += config["device_collision_boost"]
                    reasons.append(
                        f"Device Collision: Shared hardware hash with {len(linked_accounts)} other account(s)."
                    )

            if self.graph.has_node(payout_wallet_id):
                linked_accounts = [
                    n
                    for n in self.graph.predecessors(payout_wallet_id)
                    if self.graph.nodes[n].get("type") == "account"
                ]
                if len(linked_accounts) >= 2 and account_id not in linked_accounts:
                    cluster_flagged = True
                    score_boost += config["mule_hub_boost"]
                    reasons.append(
                        f"Syndicate Hub Detected: Payout wallet linked to {len(linked_accounts) + 1} distinct accounts."
                    )

            if config.get("enable_cycle_detection", True) and self.graph.has_node(payout_wallet_id):
                target_origin = (
                    source_wallet_id
                    if (source_wallet_id and self.graph.has_node(source_wallet_id))
                    else account_id
                )
                if self.graph.has_node(target_origin) and payout_wallet_id != target_origin:
                    try:
                        path = nx.shortest_path(
                            self.graph, source=payout_wallet_id, target=target_origin
                        )
                        if len(path) >= 3:
                            cluster_flagged = True
                            score_boost += config["cycle_ring_boost"]
                            loop_chain = " -> ".join(path + [payout_wallet_id])
                            reasons.append(
                                f"Circular Laundering Ring Detected: Closed loop ({loop_chain})."
                            )
                    except nx.NetworkXNoPath:
                        pass

        reason_str = " | ".join(reasons) if reasons else "Clean cluster topology."
        return cluster_flagged, score_boost, reason_str

    def trace_path(self, source: str, target: str):
        with graph_lock:
            if not self.graph.has_node(source):
                return {"found": False, "error": f"Source node '{source}' not found."}
            if not self.graph.has_node(target):
                return {"found": False, "error": f"Target node '{target}' not found."}

            try:
                path = nx.shortest_path(self.graph, source=source, target=target)
                return {"found": True, "directed": True, "hops": len(path) - 1, "path": path}
            except nx.NetworkXNoPath:
                try:
                    undirected = self.graph.to_undirected(as_view=True)
                    path = nx.shortest_path(undirected, source=source, target=target)
                    return {"found": True, "directed": False, "hops": len(path) - 1, "path": path}
                except nx.NetworkXNoPath:
                    return {"found": False, "error": "No connection exists."}

    def get_metrics(self):
        with graph_lock:
            account_nodes = [
                n for n, d in self.graph.nodes(data=True) if d.get("type") == "account"
            ]
            wallet_nodes = [
                n for n, d in self.graph.nodes(data=True) if d.get("type") == "wallet"
            ]
            device_nodes = [
                n for n, d in self.graph.nodes(data=True) if d.get("type") == "device"
            ]
            mule_hubs = [w for w in wallet_nodes if self.graph.in_degree(w) >= 2]
            shared_devices = [d for d in device_nodes if self.graph.in_degree(d) >= 2]

            return {
                "total_nodes": len(self.graph.nodes),
                "total_edges": len(self.graph.edges),
                "max_nodes_cap": self.max_nodes,
                "breakdown": {
                    "accounts": len(account_nodes),
                    "devices": len(device_nodes),
                    "wallets": len(wallet_nodes),
                },
                "flagged_mule_hubs": mule_hubs,
                "flagged_shared_devices": shared_devices,
                "mule_hub_count": len(mule_hubs),
            }

    def export_graph_json(self):
        with graph_lock:
            nodes = []
            for node, attrs in self.graph.nodes(data=True):
                node_type = attrs.get("type", "unknown")
                tx_count = attrs.get("tx_count", 1)
                in_degree = self.graph.in_degree(node)
                out_degree = self.graph.out_degree(node)

                is_mule = node_type == "wallet" and in_degree >= 2
                is_shared_device = node_type == "device" and in_degree >= 2
                has_latent_link = any(
                    d.get("relation") == "ML_LATENT_COHORT"
                    for _, _, d in list(self.graph.in_edges(node, data=True))
                    + list(self.graph.out_edges(node, data=True))
                )

                flag_reason = None
                if is_mule:
                    flag_reason = "Mule Hub"
                elif is_shared_device:
                    flag_reason = "Shared Hardware"
                elif has_latent_link:
                    flag_reason = "ML Latent Cohort"

                nodes.append({
                    "id": str(node),
                    "type": node_type,
                    "tx_count": tx_count,
                    "in_degree": in_degree,
                    "out_degree": out_degree,
                    "flagged": bool(flag_reason),
                    "flag_reason": flag_reason,
                })

            links = [
                {
                    "source": str(source),
                    "target": str(target),
                    "relation": attrs.get("relation", "EXPLICIT"),
                }
                for source, target, attrs in self.graph.edges(data=True)
            ]

            return {"nodes": nodes, "links": links}

    def clear_graph(self):
        with graph_lock:
            self.graph.clear()
            self.node_history.clear()
        with file_lock:
            if os.path.exists(DB_FILE):
                try:
                    os.remove(DB_FILE)
                except Exception:
                    pass
        return True


graph_engine = FraudGraphEngine()