# Custosa V1

**Prompt Injection Protection for Moltbot**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

Custosa is a transparent WebSocket proxy that intercepts all traffic to Moltbot Gateway and protects against prompt injection attacks. It provides real-time detection with configurable human-in-the-loop approval via Telegram for uncertain cases.

---

## Architecture

```
┌─────────────┐     ┌─────────────────────┐     ┌──────────────┐
│   Clients   │────▶│   Custosa Proxy     │────▶│ Moltbot GW   │
│  (Moltbot)  │     │   (port 18789)      │     │ (port 19789) │
└─────────────┘     └──────────┬──────────┘     └──────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Detection Engine   │
                    │  ├─ Pattern Match   │ (< 1ms)
                    │  ├─ Heuristics      │ (< 5ms)
                    │  └─ ML Classifier   │ (< 30ms, optional)
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Decision Logic    │
                    │  ├─ conf ≥ 0.9 → BLOCK
                    │  ├─ conf ≥ 0.7 → HOLD
                    │  └─ conf < 0.7 → ALLOW
                    └──────────┬──────────┘
                               │ (if HOLD)
                    ┌──────────▼──────────┐
                    │  Telegram Approval  │
                    │  └─ [✅ ALLOW] [❌ DENY]
                    └─────────────────────┘
```

---

## Installation

### One-liner (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/uditanshutomar/CustosaXopenclaw/main/install.sh | bash
```

### Homebrew (macOS/Linux)

```bash
brew install uditanshutomar/custosaxopenclaw/custosa
custosa install
```

### From Source

```bash
git clone https://github.com/uditanshutomar/CustosaXopenclaw.git
cd CustosaXopenclaw
pip install -e .
custosa install
```

The installer will:
1. Detect your Moltbot installation
2. Present GUI for Telegram bot credentials
3. Auto-configure Moltbot to route through Custosa
4. Install background service (launchd/systemd)

---

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `custosa install` | Run installation wizard |
| `custosa serve` | Start proxy server (foreground) |
| `custosa status` | Show protection status |
| `custosa start` | Start background service |
| `custosa stop` | Stop background service |
| `custosa logs` | View security logs |
| `custosa logs -f` | Follow log output |
| `custosa dashboard` | Open protected OpenClaw dashboard |
| `custosa test` | Test detection engine |
| `custosa uninstall` | Remove Custosa |

### Telegram Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Initialize bot |
| `/status` | Show Custosa status |
| `/pending` | List pending approval requests |

---

## Detection Engine

### Multi-Layer Detection

| Layer | Latency | Method |
|-------|---------|--------|
| Pattern Matching | < 1ms | Regex against 50+ known injection signatures |
| Heuristic Analysis | < 5ms | Structural anomaly detection |
| ML Classification | < 30ms | Semantic understanding (optional) |

### Pattern Categories

- **Instruction Override**: "ignore previous instructions", "disregard system prompt"
- **Persona Manipulation**: "you are now evil", "pretend to be DAN"
- **Prompt Extraction**: "reveal your system prompt", "what are your instructions"
- **Context Manipulation**: `[system]`, `<admin>`, markdown code blocks
- **Encoding Evasion**: Base64, Unicode, typoglycemia attacks
- **Data Exfiltration**: Hidden image tags, external fetch requests
- **Tool Injection**: Dangerous tool invocation patterns

### Confidence Scoring

| Score | Decision | Action |
|-------|----------|--------|
| < 0.3 | ALLOW | Forward immediately |
| 0.3 - 0.7 | ALLOW | Forward with logging |
| 0.7 - 0.9 | HOLD | Request Telegram approval |
| ≥ 0.9 | BLOCK | Reject automatically |

---

## Configuration

Configuration is stored in `~/.custosa/config.json`:

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 18789,
  "upstream_host": "127.0.0.1",
  "upstream_port": 19789,
  "block_threshold": 0.9,
  "hold_threshold": 0.7,
  "enable_ml": false,
  "telegram_bot_token": "...",
  "telegram_chat_id": "...",
  "hold_timeout_seconds": 300.0,
  "default_on_timeout": "block",
  "auto_update": true
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `listen_port` | 18789 | Port Custosa listens on (clients connect here) |
| `upstream_port` | 19789 | Port Moltbot Gateway runs on |
| `block_threshold` | 0.9 | Confidence threshold for auto-block |
| `hold_threshold` | 0.7 | Confidence threshold for Telegram approval |
| `enable_ml` | false | Enable ML classifier (requires torch) |
| `hold_timeout_seconds` | 300 | Timeout for Telegram approval (5 minutes) |
| `default_on_timeout` | "block" | Action when approval times out |

---

## Telegram Setup

1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow prompts
3. Copy your bot token
4. Message [@userinfobot](https://t.me/userinfobot) to get your chat ID
5. Enter these in the Custosa installer GUI

### Alert Format

```
🟠 CUSTOSA SECURITY ALERT 🟠

Risk Level: HIGH (78% confidence)
Alert ID: abc123def456

━━━━━━━━━━━━━━━━━━━━

Detection Reason:
Suspicious content requires review (score=0.78)

Patterns Matched:
  • instruction_override:ignore\s+...
  • heuristic:repeated_word:ignore:3

Content Preview:
[truncated message content]

━━━━━━━━━━━━━━━━━━━━

⏱️ Auto-DENY in 5 minutes if no action taken.

[✅ ALLOW] [❌ DENY]
```

---

## Security Model

### Threat Categories Addressed

Based on OWASP LLM Top 10 2025 and CrowdStrike's 150+ injection technique taxonomy:

1. **Direct Prompt Injection** (LLM01)
   - Explicit instruction override attempts
   - Role/persona manipulation
   - Context window attacks

2. **Indirect Prompt Injection** (via processed content)
   - Hidden instructions in documents
   - Malicious web content
   - Tool poisoning

### Defense Strategy

- **Fail-Closed**: Uncertain requests default to DENY on timeout
- **Defense-in-Depth**: Multiple detection layers with different strengths
- **Human-in-Loop**: Telegram approval for edge cases
- **Audit Trail**: All decisions logged with content hashes (not content)

---

## Development

### Setup

```bash
git clone https://github.com/uditanshutomar/CustosaXopenclaw.git
cd CustosaXopenclaw
pip install -e ".[dev]"
```

### Testing

```bash
# Run tests
pytest

# Test detection engine
custosa test -v

# Run with mock Telegram
custosa serve --mock-telegram
```

### Project Structure

```
├── src/
│   ├── core/
│   │   └── proxy.py          # WebSocket proxy
│   ├── detection/
│   │   └── engine.py         # Detection engine
│   ├── telegram/
│   │   └── bot.py            # Telegram approval bot
│   ├── installer/
│   │   └── setup.py          # Installation wizard
│   └── main.py               # CLI entry point
├── tests/
├── dist/
│   └── custosa.rb            # Homebrew formula
├── pyproject.toml
└── README.md
```

---

## Roadmap

### v1.0 (Current)
- [x] WebSocket proxy with message interception
- [x] Multi-layer prompt injection detection
- [x] Telegram human-in-the-loop approval
- [x] Auto-configuration of Moltbot
- [x] macOS/Linux service installation

### v1.1 (Planned)
- [ ] ML classifier with fine-tuned DeBERTa model
- [ ] Web dashboard for monitoring
- [ ] Alert batching to prevent fatigue
- [ ] Configurable detection rules via YAML

### v2.0 (Future)
- [ ] Windows support
- [ ] Multi-agent support
- [ ] Audit log export (SIEM integration)
- [ ] Custom policy rules DSL

---

## License

Proprietary - see [LICENSE](LICENSE) for details.

Personal, non-commercial use permitted. Commercial licensing available.

---

## Acknowledgments

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CrowdStrike Prompt Injection Research](https://www.crowdstrike.com/en-us/blog/indirect-prompt-injection-attacks-hidden-ai-risks/)
- [Microsoft Prompt Shields](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection)
- [Moltbot](https://docs.molt.bot/) by the Moltbot team
