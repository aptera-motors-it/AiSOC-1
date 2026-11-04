from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HONEYTOKEN_",
        env_file=".env",
        populate_by_name=True,
        extra="ignore",
    )

    # Database.
    #
    # ``env_prefix`` means every other field here is read as
    # ``HONEYTOKEN_<FIELD>``, and this one used to be as well — while
    # ``docker-compose.yml`` set plain ``DATABASE_URL`` on this service, as it
    # does for every other. The variable was therefore inert: the service fell
    # back to the default below, which names the *owner* role, so pointing the
    # deployment at the DML-only runtime role changed nothing here.
    #
    # Both spellings now resolve, unprefixed first, the same convention
    # ``services/ueba`` and ``services/fusion`` already use. The alias replaces
    # the prefix for this field only; the rest of the settings are untouched.
    database_url: str = Field(
        default="postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc",
        validation_alias=AliasChoices("DATABASE_URL", "HONEYTOKEN_DATABASE_URL"),
    )

    # Webhook alerting. ``alert_webhook_secret`` previously defaulted to the
    # literal string ``"changeme"`` — anyone running this service with the
    # defaults would sign every outbound honeytoken alert with a public secret,
    # so a downstream verifier couldn't distinguish a real trigger from a
    # forged one. The secret still defaults to empty, and a delivery is refused
    # until a real HMAC secret is set.
    #
    # The URL does not. An empty URL used to make ``send_alert`` return false
    # and log that it was skipping, so a trip on the default stack produced no
    # alert and nothing retried it. The default is the API route that publishes
    # the trip onto ``raw_events``. Compose sets the same value explicitly.
    alert_webhook_url: str = "http://api:8000/api/v1/internal/honeytoken-alerts"
    alert_webhook_secret: str = ""
    # Seconds between passes over trips whose alert has not been accepted.
    # A pass that still has undelivered rows waits longer, up to a cap, so a
    # dead receiver is not polled at this interval forever.
    alert_retry_seconds: float = 5.0

    # Token defaults
    token_ttl_days: int = 365

    # OTel
    otel_endpoint: str = "http://localhost:4317"
    service_name: str = "aisoc-honeytokens"

    # API
    host: str = "0.0.0.0"
    port: int = 8005


settings = Settings()
