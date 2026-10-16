# SENTINEL — the guard for AI agents

Agents now read untrusted content, hold credentials, and act on the world. Two
things go wrong constantly:

1. **Secrets and personal data leak** — an agent pastes an API key or a customer's
   ID into a log, a message, a commit, or someone else's model.
2. **Prompt injection** — untrusted text smuggles in instructions ("ignore all
   previous instructions…"), and the agent obeys.

SENTINEL is a small plug that sits in front of those moments and answers one
question: **is this text safe to send, store, or act on?** It ships as an MCP
server, so Claude Code, Claude Desktop, or any MCP client can call it.

## Tools

| Tool | What it does |
|------|--------------|
| `sentinel_scan` | Full report: secrets, PII, injection — severity-ranked, with a verdict |
| `sentinel_redact` | Returns the text with secrets and PII masked out |
| `sentinel_check_injection` | Injection-only analysis with a risk verdict |
| `sentinel_demo` | Runs a built-in sample through everything |

## What it catches

- **Secrets:** private key blocks, AWS keys, GitHub/Anthropic/OpenAI/Google/Slack/Stripe tokens, JWTs, password assignments.
- **Personal data (unique angle — India-specific):** Aadhaar, PAN, UPI ID, IFSC — plus email, phone (incl. spaced Indian numbers), and payment cards (Luhn-checked). Most guards miss the Indian IDs.
- **Prompt injection:** instruction overrides, persona hijacks, system-prompt exfiltration, jailbreak phrases, fake system turns, hidden zero-width characters, encoded payloads.

Each finding gets a severity, and the scan returns a verdict: **BLOCK**,
**REVIEW**, or **CLEAN**.

## Quick start

    pip install mcp
    python3 sentinel_mcp_server.py

Connect it to Claude Code:

    claude mcp add sentinel -- python3 /full/path/to/sentinel_mcp_server.py

Or add a `sentinel` entry to Claude Desktop's `claude_desktop_config.json`.

Then ask the agent to scan text before it sends or stores it.

## Honest limits

SENTINEL is **pattern-based** — fast, private (nothing leaves your machine), and
good at the common cases. It is not a substitute for real secret management, and
it can produce false positives and misses. Treat a **CLEAN** verdict as "nothing
obvious," not as a guarantee.

## License

MIT
