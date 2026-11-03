"""Per-service memory and pid ceilings for the production compose overlay.

The README deployment-profile table (`README.md`, same figures in
`apps/docs/docs/architecture.md`) publishes **~8 GB** for CORE and **~12 GB**
for `full`. Those totals are measured budgets, not per-container guesses. This
module holds the per-service ceilings the overlay must declare so a runaway
process cannot consume the whole VM: limits follow `docker-compose.yml`
``mem_limit`` where the base file already measured one, Helm
``resources.limits.memory`` for application services on a single host, and the
architecture page's ollama note (~3 GiB while answering → 4 GiB cap).

``pids_limit`` is expressed as ``deploy.resources.limits.pids`` so Compose v2.29+
does not reject the project for conflicting pid keys.
"""

from __future__ import annotations

from typing import NamedTuple


class ProdBounds(NamedTuple):
    memory: str
    pids_limit: int


# Keys are service names in docker-compose.yml / docker-compose.prod.yml.
PRODUCTION_SERVICE_BOUNDS: dict[str, ProdBounds] = {
    "preflight-secrets": ProdBounds("256M", 256),
    "postgres": ProdBounds("1G", 1024),
    "redis": ProdBounds("512M", 512),
    "zookeeper": ProdBounds("512M", 2048),
    "kafka": ProdBounds("1536M", 4096),
    "qdrant": ProdBounds("512M", 512),
    "api": ProdBounds("1G", 512),
    "ingest-worker": ProdBounds("512M", 512),
    "fusion": ProdBounds("2G", 512),
    "agents": ProdBounds("4G", 512),
    "actions": ProdBounds("512M", 512),
    "connectors": ProdBounds("768M", 512),
    "threatintel": ProdBounds("512M", 512),
    "realtime": ProdBounds("512M", 512),
    "litellm": ProdBounds("512M", 512),
    "ollama": ProdBounds("4G", 4096),
    "ollama-pull": ProdBounds("512M", 256),
    "mcp": ProdBounds("512M", 512),
    "web": ProdBounds("512M", 512),
    "neo4j": ProdBounds("1G", 2048),
    "clickhouse": ProdBounds("1G", 2048),
    "opensearch": ProdBounds("2G", 2048),
    "kafka-ui": ProdBounds("512M", 512),
    "alertmanager": ProdBounds("256M", 512),
    "enrichment": ProdBounds("1G", 512),
    "honeytokens": ProdBounds("1G", 512),
    "escalations": ProdBounds("256M", 512),
    "osquery-tls": ProdBounds("512M", 512),
    "otel-collector": ProdBounds("512M", 512),
    "prometheus": ProdBounds("1G", 512),
    "purple-team": ProdBounds("1G", 512),
    "slack-bot": ProdBounds("512M", 512),
    "teams-bot": ProdBounds("512M", 512),
    "tempo": ProdBounds("512M", 512),
    "ueba": ProdBounds("2G", 512),
    "grafana": ProdBounds("512M", 512),
}


def bounds_for(service: str) -> ProdBounds | None:
    return PRODUCTION_SERVICE_BOUNDS.get(service)
