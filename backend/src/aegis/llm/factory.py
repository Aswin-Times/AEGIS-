from aegis.config import Settings
from aegis.llm.adapter import LlmProvider


def build_llm_provider(settings: Settings) -> LlmProvider | None:
    """None unless explicitly configured. A partial configuration stops startup, loudly."""
    if settings.llm_provider == "none":
        return None
    if settings.llm_api_key is None:
        raise ValueError("AEGIS_LLM_API_KEY is required when AEGIS_LLM_PROVIDER is set")
    # Imported here so the SDK stays optional: nothing else in AEGIS needs it.
    from aegis.llm.anthropic_provider import AnthropicProvider

    return AnthropicProvider(
        api_key=settings.llm_api_key.get_secret_value(), model=settings.llm_model
    )
