"""Root-compose postgres, redis, and kafka-ui must use patch-level image tags.

Floating tags (``postgres:16-alpine``, ``redis:7-alpine``,
``provectuslabs/kafka-ui:latest``) move on every upstream publish, so a stack
that pins only a major/minor line is not reproducible.
"""

from __future__ import annotations

import pathlib
import re

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
ROOT_COMPOSE = REPO / "docker-compose.yml"

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

    def test_floating_tags_are_rejected(self, tmp_path: pathlib.Path) -> None:
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
