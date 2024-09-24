from __future__ import annotations

from typing import Any, override

import click
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

from langchain_prompt_protection.runnables import (
    MaliciousDomainsError,
    MaliciousIpAddressesError,
    MaliciousUrlsError,
    PangeaAuditRunnable,
    PangeaDomainIntelGuard,
    PangeaIpIntelGuard,
    PangeaRedactRunnable,
    PangeaUrlIntelGuard,
)


class SecretStrParamType(click.ParamType):
    name = "secret"

    @override
    def convert(self, value: Any, param: click.Parameter | None = None, ctx: click.Context | None = None) -> SecretStr:
        if isinstance(value, SecretStr):
            return value

        return SecretStr(value)


SECRET_STR = SecretStrParamType()


@click.command()
@click.option("--model", default="gpt-4o-mini", show_default=True, required=True, help="OpenAI model.")
@click.option(
    "--audit-token",
    envvar="PANGEA_AUDIT_TOKEN",
    type=SECRET_STR,
    required=True,
    help="Pangea Secure Audit Log API token. May also be set via the `PANGEA_AUDIT_TOKEN` environment variable.",
)
@click.option(
    "--audit-config-id",
    help="Pangea Secure Audit Log configuration ID.",
)
@click.option(
    "--domain-intel-token",
    envvar="PANGEA_DOMAIN_INTEL_TOKEN",
    type=SECRET_STR,
    required=True,
    help="Pangea Domain Intel API token. May also be set via the `PANGEA_DOMAIN_INTEL_TOKEN` environment variable.",
)
@click.option(
    "--ip-intel-token",
    envvar="PANGEA_IP_INTEL_TOKEN",
    type=SECRET_STR,
    required=True,
    help="Pangea IP Intel API token. May also be set via the `PANGEA_IP_INTEL_TOKEN` environment variable.",
)
@click.option(
    "--redact-token",
    envvar="PANGEA_REDACT_TOKEN",
    type=SECRET_STR,
    required=True,
    help="Pangea Redact API token. May also be set via the `PANGEA_REDACT_TOKEN` environment variable.",
)
@click.option(
    "--redact-config-id",
    help="Pangea Redact configuration ID.",
)
@click.option(
    "--url-intel-token",
    envvar="PANGEA_URL_INTEL_TOKEN",
    type=SECRET_STR,
    required=True,
    help="Pangea URL Intel API token. May also be set via the `PANGEA_URL_INTEL_TOKEN` environment variable.",
)
@click.option(
    "--pangea-domain",
    envvar="PANGEA_DOMAIN",
    default="aws.us.pangea.cloud",
    show_default=True,
    required=True,
    help="Pangea API domain. May also be set via the `PANGEA_DOMAIN` environment variable.",
)
@click.option(
    "--openai-api-key",
    envvar="OPENAI_API_KEY",
    type=SECRET_STR,
    required=True,
    help="OpenAI API key. May also be set via the `OPENAI_API_KEY` environment variable.",
)
@click.argument("prompt")
def main(
    *,
    prompt: str,
    audit_token: SecretStr,
    audit_config_id: str | None = None,
    domain_intel_token: SecretStr,
    ip_intel_token: SecretStr,
    redact_token: SecretStr,
    redact_config_id: str | None = None,
    url_intel_token: SecretStr,
    pangea_domain: str,
    model: str,
    openai_api_key: SecretStr,
) -> None:
    chain = (
        ChatPromptTemplate.from_messages([("user", "{input}")])
        | PangeaAuditRunnable(token=audit_token, domain=pangea_domain, config_id=audit_config_id)
        | PangeaRedactRunnable(token=redact_token, domain=pangea_domain, config_id=redact_config_id)
        | PangeaDomainIntelGuard(token=domain_intel_token, domain=pangea_domain)
        | PangeaIpIntelGuard(token=ip_intel_token, domain=pangea_domain)
        | PangeaUrlIntelGuard(token=url_intel_token, domain=pangea_domain)
        | ChatOpenAI(model=model, api_key=openai_api_key)
        | StrOutputParser()
    )
    try:
        click.echo(chain.invoke({"input": prompt}))
    except MaliciousDomainsError:
        raise click.BadParameter("The prompt contained malicious domains.")
    except MaliciousIpAddressesError:
        raise click.BadParameter("The prompt contained malicious IP addresses.")
    except MaliciousUrlsError:
        raise click.BadParameter("The prompt contained malicious URLs.")


if __name__ == "__main__":
    main()
