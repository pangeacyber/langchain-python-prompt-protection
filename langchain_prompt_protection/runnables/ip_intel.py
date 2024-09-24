from __future__ import annotations

import re
from typing import override

from langchain_core.messages import HumanMessage
from langchain_core.prompt_values import PromptValue
from langchain_core.runnables import RunnableConfig, RunnableSerializable
from pangea import PangeaConfig
from pangea.services import IpIntel
from pydantic import SecretStr

__all__ = ["MaliciousIpAddressesError", "PangeaIpIntelGuard"]

IP_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


class MaliciousIpAddressesError(RuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class PangeaIpIntelGuard(RunnableSerializable[PromptValue, PromptValue]):
    """
    Runnable that checks the reputation of IP addresses found in prompts using
    the Pangea IP Intel service.
    """

    _client: IpIntel
    _threshold: int

    def __init__(self, *, token: SecretStr, domain: str = "aws.us.pangea.cloud", threshold: int = 70) -> None:
        """
        Args:
            token: Pangea IP Intel API token.
            domain: Pangea API domain.
            threshold: Threshold score for an IP address to be considered malicious.
        """

        super().__init__()
        self._client = IpIntel(token=token.get_secret_value(), config=PangeaConfig(domain=domain))
        self._threshold = threshold

    @override
    def invoke(self, input: PromptValue, config: RunnableConfig | None = None) -> PromptValue:
        # Retrieve latest human message.
        messages = input.to_messages()
        human_messages = [message for message in messages if isinstance(message, HumanMessage)]
        text = human_messages[-1].content
        assert isinstance(text, str)

        # Find all IP addresses in the text.
        ip_addresses = re.findall(IP_RE, text)
        if len(ip_addresses) == 0:
            return input

        # Check the reputation of each IP address.
        intel = self._client.reputation_bulk(ip_addresses)
        assert intel.result
        if any(x.score >= self._threshold for x in intel.result.data.values()):
            raise MaliciousIpAddressesError("One or more IP addresses have a malice score above the threshold.")

        # Pass on the input unchanged.
        return input
