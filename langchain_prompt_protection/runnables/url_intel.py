from __future__ import annotations

import re
from typing import Any, override

from langchain_core.messages import HumanMessage
from langchain_core.prompt_values import PromptValue
from langchain_core.runnables import RunnableConfig, RunnableSerializable
from pangea import PangeaConfig
from pangea.services import UrlIntel
from pydantic import SecretStr

__all__ = ["MaliciousUrlsError", "PangeaUrlIntelGuard"]

URL_RE = r"https?://(?:[-\w.]|%[\da-fA-F]{2})+"


class MaliciousUrlsError(RuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class PangeaUrlIntelGuard(RunnableSerializable[PromptValue, PromptValue]):
    """
    Runnable that checks the reputation of URLs found in prompts using the
    Pangea URL Intel service.
    """

    _client: UrlIntel
    _threshold: int

    def __init__(self, *, token: SecretStr, domain: str = "aws.us.pangea.cloud", threshold: int = 70) -> None:
        """
        Args:
            token: Pangea URL Intel API token.
            domain: Pangea API domain.
            threshold: Threshold score for a URL to be considered malicious.
        """

        super().__init__()
        self._client = UrlIntel(token=token.get_secret_value(), config=PangeaConfig(domain=domain))
        self._threshold = threshold

    @override
    def invoke(self, input: PromptValue, config: RunnableConfig | None = None, **kwargs: Any) -> PromptValue:
        # Retrieve latest human message.
        messages = input.to_messages()
        human_messages = [message for message in messages if isinstance(message, HumanMessage)]
        text = human_messages[-1].content
        assert isinstance(text, str)

        # Find all URLs in the text.
        urls = re.findall(URL_RE, text)
        if len(urls) == 0:
            return input

        # Check the reputation of each URL.
        intel = self._client.reputation_bulk(urls)
        assert intel.result
        if any(x.score >= self._threshold for x in intel.result.data.values()):
            raise MaliciousUrlsError("One or more URLs have a malice score above the threshold.")

        # Pass on the input unchanged.
        return input
