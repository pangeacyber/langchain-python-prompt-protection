from __future__ import annotations

import re
from typing import override

from langchain_core.messages import HumanMessage
from langchain_core.prompt_values import PromptValue
from langchain_core.runnables import RunnableConfig, RunnableSerializable
from pangea import PangeaConfig
from pangea.services import DomainIntel
from pydantic import SecretStr

__all__ = ["MaliciousDomainsError", "PangeaDomainIntelGuard"]

DOMAIN_RE = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"


class MaliciousDomainsError(RuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class PangeaDomainIntelGuard(RunnableSerializable[PromptValue, PromptValue]):
    """
    Runnable that checks the reputation of domains found in prompts using the
    Pangea Domain Intel service.
    """

    _client: DomainIntel
    _threshold: int

    def __init__(self, *, token: SecretStr, domain: str = "aws.us.pangea.cloud", threshold: int = 70) -> None:
        """
        Args:
            token: Pangea Domain Intel API token.
            domain: Pangea API domain.
            threshold: Threshold score for a domain to be considered malicious.
        """

        super().__init__()
        self._client = DomainIntel(token=token.get_secret_value(), config=PangeaConfig(domain=domain))
        self._threshold = threshold

    @override
    def invoke(self, input: PromptValue, config: RunnableConfig | None = None) -> PromptValue:
        # Retrieve latest human message.
        messages = input.to_messages()
        human_messages = [message for message in messages if isinstance(message, HumanMessage)]
        text = human_messages[-1].content
        assert isinstance(text, str)

        # Find all domains in the text.
        domains = re.findall(DOMAIN_RE, text)
        if len(domains) == 0:
            return input

        # Check the reputation of each domain.
        intel = self._client.reputation_bulk(domains)
        assert intel.result
        if any(x.score >= self._threshold for x in intel.result.data.values()):
            raise MaliciousDomainsError("One or more domains have a malice score above the threshold.")

        # Pass on the input unchanged.
        return input
