from __future__ import annotations

from typing import override

from langchain_core.messages import HumanMessage
from langchain_core.prompt_values import ChatPromptValue, PromptValue
from langchain_core.runnables import RunnableConfig, RunnableSerializable
from pangea import PangeaConfig
from pangea.services import Redact
from pydantic import SecretStr

__all__ = ["PangeaRedactRunnable"]


class PangeaRedactRunnable(RunnableSerializable[PromptValue, PromptValue]):
    """
    Runnable that redacts sensitive information from prompts using the Pangea
    Redact service.
    """

    _client: Redact

    def __init__(self, *, token: SecretStr, config_id: str | None = None, domain: str = "aws.us.pangea.cloud") -> None:
        """
        Args:
            token: Pangea Redact API token.
            config_id: Pangea Redact configuration ID.
            domain: Pangea API domain.
        """

        super().__init__()
        self._client = Redact(token=token.get_secret_value(), config=PangeaConfig(domain=domain), config_id=config_id)

    @override
    def invoke(self, input: PromptValue, config: RunnableConfig | None = None) -> PromptValue:
        # Retrieve latest human message.
        messages = input.to_messages()
        human_messages = [message for message in messages if isinstance(message, HumanMessage)]
        text = human_messages[-1].content
        assert isinstance(text, str)

        # Redact any sensitive text.
        redacted = self._client.redact(text=text)
        assert redacted.result

        # Replace the last human message with the redacted text.
        return ChatPromptValue(messages=messages[:-1] + [HumanMessage(content=redacted.result.redacted_text or text)])
