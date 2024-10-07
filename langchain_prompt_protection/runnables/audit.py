from __future__ import annotations

from typing import Any, override

from langchain_core.messages import HumanMessage
from langchain_core.prompt_values import PromptValue
from langchain_core.runnables import RunnableConfig, RunnableSerializable
from pangea import PangeaConfig
from pangea.services import Audit
from pydantic import SecretStr

__all__ = ["PangeaAuditRunnable"]


class PangeaAuditRunnable(RunnableSerializable[PromptValue, PromptValue]):
    """
    Runnable that creates an event in Pangea's Secure Audit Log when a prompt is
    received.
    """

    _client: Audit

    def __init__(self, *, token: SecretStr, config_id: str | None = None, domain: str = "aws.us.pangea.cloud") -> None:
        """
        Args:
            token: Pangea Secure Audit Log API token.
            config_id: Pangea Secure Audit Log configuration ID.
            domain: Pangea API domain.
        """

        super().__init__()
        self._client = Audit(token=token.get_secret_value(), config=PangeaConfig(domain=domain), config_id=config_id)

    @override
    def invoke(self, input: PromptValue, config: RunnableConfig | None = None, **kwargs: Any) -> PromptValue:
        # Retrieve latest human message.
        messages = input.to_messages()
        human_messages = [message for message in messages if isinstance(message, HumanMessage)]
        text = human_messages[-1].content
        assert isinstance(text, str)

        # Create an audit log for it.
        self._client.log_bulk([{"message": "Received a human prompt for a LLM.", "old": text, "new": text}])

        # Pass on the input unchanged.
        return input
