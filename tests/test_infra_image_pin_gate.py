"""Infrastructure images in the root compose file must carry patch-level tags.

Floating tags such as ``postgres:16-alpine``, ``redis:7-alpine``, and
``provectuslabs/kafka-ui:latest`` move on every upstream publish. A stack
that pins only the major/minor line (or ``latest``) is not reproducible and
cannot be reviewed for a known CVE level. The datastore services named in
``docker-compose.yml`` are third-party images every operator pulls; they need
explicit patch pins like the Confluent and ClickHouse lines already use.
"""

from __future__ import annotations

import pathlib
import re

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
ROOT_COMPOSE = REPO / "docker-compose.yml"

#: Services whose ``image:`` must name a patch-level tag, not a rolling alias.
PINNED_INFRA_SERVICES: dict[str, re.Pattern[str]] = {
    "postgres": re.compile(r"^postgres:16\.\d+(?:\.\d+)?-alpine(?:3\.\d+)?$"),
    "redis": re.compile(r"^redis:7\.\d+\.\d+-alpine(?:3\.\d+)?$"),
    "kafka-ui": re.compile(r"^provectuslabs/kafka-ui:v\d+\.\d+\.\d+$"),
}


def _service_images(path: pathlib.Path) -> dict[str, str]:
    services = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("services") or {}
    out: dict[str, str] = {}
    for name, spec in services.items():
        image = (spec or {}).get("image")
        if image:
            out[str(name)] = str(image).strip()
    return out


def _unpinned_infra_images(path: pathlib.Path) -> list[str]:
    images = _service_images(path)
    offenders: list[str] = []
    for service, pattern in PINNED_INFRA_SERVICES.items():
        image = images.get(service)
        if not image:
            offenders.append(f"{path.name}:{service}: missing image")
            continue
        if image.endswith(":latest"):
            offenders.append(f"{path.name}:{service}: {image} (rolling latest)")
            continue
        if not pattern.fullmatch(image):
            offenders.append(f"{path.name}:{service}: {image} (not patch-pinned)")
    return offenders


class TestRootComposeInfraImagesArePatchPinned:
    def test_postgres_redis_and_kafka_ui_carry_patch_tags(self) -> None:
        offenders = _unpinned_infra_images(ROOT_COMPOSE)
        assert not offenders, "these infrastructure images must name a patch-level tag, not a rolling alias:\n  " + "\n  ".join(offenders)

    def test_the_gate_catches_floating_tags_it_was_written_for(self, tmp_path: pathlib.Path) -> None:
        broken = tmp_path / "docker-compose.yml"
        broken.write_text(
            yaml.safe_dump(
                {
                    "services": {
                        "postgres": {"image": "postgres:16-alpine"},
                        "redis": {"image": "redis:7-alpine"},
                        "kafka-ui": {"image": "provectuslabs/kafka-ui:latest"},
                    }
                }
            ),
            encoding="utf-8",
        )
        offenders = _unpinned_infra_images(broken)
        assert len(offenders) == 3
        assert all("not patch-pinned" in row or "rolling latest" in row for row in offenders)

    def test_patch_pins_pass(self, tmp_path: pathlib.Path) -> None:
        fixed = tmp_path / "docker-compose.yml"
        fixed.write_text(
            yaml.safe_dump(
                {
                    "services": {
                        "postgres": {"image": "postgres:16.15-alpine"},
                        "redis": {"image": "redis:7.4.12-alpine"},
                        "kafka-ui": {"image": "provectuslabs/kafka-ui:v0.7.2"},
                    }
                }
            ),
            encoding="utf-8",
        )
        assert not _unpinned_infra_images(fixed)
