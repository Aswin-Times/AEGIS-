"""Claude through the official SDK. Installed only with the optional `llm` extra."""

from typing import Any

import anthropic

from aegis.llm.adapter import LlmError, LlmRefused, LlmRequest, LlmTimeout

DEFAULT_MODEL = "claude-opus-5-5"
_MAX_TOKENS = 16_000
_MAX_RETRIES = 1
# On a classifier decline, the API retries on another model. A final decline is still reported.
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, http_client: Any = None) -> None:
        self.model = model
        self._client = anthropic.Anthropic(
            api_key=api_key, max_retries=_MAX_RETRIES, http_client=http_client
        )

    def complete(self, request: LlmRequest) -> str:
        try:
            client = self._client.with_options(timeout=request.timeout_seconds)
            response = client.beta.messages.create(
                model=self.model,
                max_tokens=_MAX_TOKENS,
                system=request.system,
                messages=[{"role": "user", "content": request.user}],
                output_config={
                    "effort": "medium",
                    "format": {"type": "json_schema", "schema": request.schema},
                },
                betas=[_FALLBACK_BETA],
                fallbacks="default",
            )
        except anthropic.APITimeoutError as error:
            raise LlmTimeout("The provider timed out") from error
        except anthropic.APIStatusError as error:
            # Not the error's text: a provider response is untrusted and is not to be logged.
            raise LlmError(f"The provider returned status {error.status_code}") from None
        except anthropic.APIConnectionError as error:
            raise LlmError("The provider could not be reached") from error

        if response.stop_reason == "refusal":
            raise LlmRefused("The provider declined this request")
        if response.stop_reason != "end_turn":
            raise LlmError(f"The provider stopped early: {response.stop_reason}")
        return "".join(block.text for block in response.content if block.type == "text")
