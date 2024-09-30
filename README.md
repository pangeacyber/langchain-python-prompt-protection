# langchain-python-prompt-protection

An example CLI tool in Python that demonstrates how to integrate Pangea services
into a LangChain app to capture and filter what users are sending to LLMs:

- [Secure Audit Log][] — Create an event when a human prompt is received.
- [Redact][] — Remove sensitive information from prompts.
- [Domain Intel][] — Stop prompts with malicious domains from going to the LLM.
- [IP Intel][] — Stop prompts with malicious IP addresses from going to the LLM.
- [URL Intel][] — Stop prompts with malicious URLs from going to the LLM.

## Prerequisites

- Python v3.12 or greater.
- pip v24.2 or [uv][] v0.4.5.
- A [Pangea account][Pangea signup] with all of the above services enabled.
- An [OpenAI API key][OpenAI API keys].

## Setup

```shell
git clone https://github.com/pangeacyber/langchain-python-prompt-protection.git
cd langchain-python-prompt-protection
```

If using pip:

```shell
python -m venv .venv
source .venv/bin/activate
pip install .
```

Or, if using uv:

```shell
uv sync
source .venv/bin/activate
```

The sample can then be executed with:

```shell
python -m langchain_prompt_protection "Give me information on John Smith."
```

## Usage

```
Usage: python -m langchain_prompt_protection [OPTIONS] PROMPT

Options:
  --model TEXT                 OpenAI model.  [default: gpt-4o-mini; required]
  --audit-token SECRET         Pangea Secure Audit Log API token. May also be
                               set via the `PANGEA_AUDIT_TOKEN` environment
                               variable.  [required]
  --audit-config-id TEXT       Pangea Secure Audit Log configuration ID.
  --domain-intel-token SECRET  Pangea Domain Intel API token. May also be set
                               via the `PANGEA_DOMAIN_INTEL_TOKEN` environment
                               variable.  [required]
  --ip-intel-token SECRET      Pangea IP Intel API token. May also be set via
                               the `PANGEA_IP_INTEL_TOKEN` environment
                               variable.  [required]
  --redact-token SECRET        Pangea Redact API token. May also be set via
                               the `PANGEA_REDACT_TOKEN` environment variable.
                               [required]
  --redact-config-id TEXT      Pangea Redact configuration ID.
  --url-intel-token SECRET     Pangea URL Intel API token. May also be set via
                               the `PANGEA_URL_INTEL_TOKEN` environment
                               variable.  [required]
  --pangea-domain TEXT         Pangea API domain. May also be set via the
                               `PANGEA_DOMAIN` environment variable.
                               [default: aws.us.pangea.cloud; required]
  --openai-api-key SECRET      OpenAI API key. May also be set via the
                               `OPENAI_API_KEY` environment variable.
                               [required]
  --help                       Show this message and exit.
```

Audit logs and the results of any redactions can be viewed at the
[Secure Audit Log Viewer][].

[Secure Audit Log]: https://pangea.cloud/docs/audit/
[Secure Audit Log Viewer]: https://console.pangea.cloud/service/audit/logs
[Redact]: https://pangea.cloud/docs/redact/
[Domain Intel]: https://pangea.cloud/docs/domain-intel/
[IP Intel]: https://pangea.cloud/docs/ip-intel/
[URL Intel]: https://pangea.cloud/docs/url-intel/
[Pangea signup]: https://pangea.cloud/signup
[OpenAI API keys]: https://platform.openai.com/api-keys
[uv]: https://docs.astral.sh/uv/
