import ipaddress
import re
from fastapi import Request


class VPNDemasker:
    def __init__(self):
        # Known commercial VPN, Tor exit, and cloud datacenter CIDR blocks
        self.datacenter_cidrs = [
            ipaddress.ip_network("185.220.100.0/22"),  # Tor Exit Nodes
            ipaddress.ip_network("104.16.0.0/12"),     # Cloudflare / Warp / CDN Proxies
            ipaddress.ip_network("45.33.0.0/16"),      # Linode / Akamai Cloud VPS
            ipaddress.ip_network("167.99.0.0/16"),     # DigitalOcean VPN Exit Nodes
            ipaddress.ip_network("198.51.100.0/24"),   # Synthetic Proxy / VPN Simulation Block
            ipaddress.ip_network("203.0.113.0/24"),    # High-Risk Anonymizer Block
        ]
        self.proxy_headers = ("x-forwarded-for", "via", "forwarded", "x-real-ip", "proxy-connection")

    def _extract_ip(self, ip_subnet_or_ip: str) -> ipaddress.IPv4Address | None:
        cleaned = ip_subnet_or_ip.split("/")[0].strip()
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            return ip_obj if isinstance(ip_obj, ipaddress.IPv4Address) else None
        except ValueError:
            return None

    def inspect_request(
        self,
        declared_ip_subnet: str,
        device_hash: str,
        graph,
        request: Request | None = None,
        client_timezone: str | None = None,
    ) -> dict:
        risk_penalty = 0.0
        signals = []
        demasked_origin = declared_ip_subnet

        # 1. Check HTTP Proxy Leakage Headers (X-Forwarded-For / Via)
        if request is not None:
            xff = request.headers.get("x-forwarded-for")
            if xff:
                hops = [h.strip() for h in xff.split(",") if h.strip()]
                if len(hops) >= 2:
                    risk_penalty += 0.35
                    demasked_origin = hops[0]
                    signals.append(f"Multi-Hop Proxy Chain ({len(hops)} hops; true origin={hops[0]})")
            for hdr in ("via", "forwarded", "proxy-connection"):
                if hdr in request.headers:
                    risk_penalty += 0.25
                    signals.append(f"Anonymizer Header Exposed ({hdr.upper()})")

        # 2. Check Datacenter / VPN Exit CIDR Membership
        ip_obj = self._extract_ip(declared_ip_subnet)
        is_datacenter = False
        if ip_obj:
            for cidr in self.datacenter_cidrs:
                if ip_obj in cidr:
                    is_datacenter = True
                    risk_penalty += 0.45
                    signals.append(f"VPN/Datacenter ASN Exit ({cidr})")
                    break

        # 3. Check Device Subnet-Hopping Velocity in Live Graph
        subnet_hops = 0
        if graph.has_node(device_hash):
            connected_accounts = [
                u for u, _ in graph.in_edges(device_hash) if graph.nodes[u].get("type") == "account"
            ]
            distinct_subnets = set()
            for acc in connected_accounts:
                for _, v, edge_data in graph.out_edges(acc, data=True):
                    if edge_data.get("relation") == "FROM_SUBNET":
                        distinct_subnets.add(v)
            distinct_subnets.add(declared_ip_subnet)
            subnet_hops = len(distinct_subnets)
            if subnet_hops >= 3:
                risk_penalty += 0.40
                signals.append(f"VPN IP-Hopping ({subnet_hops} distinct /24 subnets on {device_hash})")

        # 4. Timezone / Geo-Locale Drift Check (Optional Header/Field)
        if client_timezone and ip_obj:
            # Example heuristic: Indian residential ISP range vs non-Asia timezone
            if str(ip_obj).startswith(("49.", "103.", "106.", "117.")) and not re.search(
                r"(Asia/Kolkata|Asia/Calcutta|\+05:30)", client_timezone, re.IGNORECASE
            ):
                risk_penalty += 0.30
                signals.append(f"Timezone/IP Geo-Mismatch ({client_timezone} vs IN subnet)")

        risk_penalty = round(min(risk_penalty, 0.95), 3)
        is_masked = risk_penalty >= 0.35

        return {
            "is_vpn_or_proxy": is_masked,
            "is_datacenter_exit": is_datacenter,
            "vpn_risk_score": risk_penalty,
            "demasked_origin": demasked_origin,
            "subnet_hops": subnet_hops,
            "reason": " | ".join(signals) if signals else "Clean Residential ISP",
        }


vpn_demasker = VPNDemasker()