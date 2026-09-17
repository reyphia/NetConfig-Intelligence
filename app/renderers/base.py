"""Abstract renderer contract."""

from abc import ABC, abstractmethod

from app.models.device import Device


class ConfigRenderer(ABC):
    target_platform: str = "unknown platform"
    target_syntax_notes: str = ""

    @abstractmethod
    def render(self, device: Device) -> str:
        """Render a normalized device into vendor-specific configuration."""
        raise NotImplementedError

    def compatibility_warning(self) -> str:
        """Spec-required honesty note: NetConfig Intelligence never claims a
        generated config is guaranteed to apply cleanly on every firmware
        version - this string is surfaced next to every export/replay plan."""
        base = (
            f"Generated for {self.target_platform}. Command syntax can vary between "
            "firmware/software versions - review before applying to a production device."
        )
        return f"{base} {self.target_syntax_notes}".strip()
