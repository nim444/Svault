# Svault

> The secret manager that knows an AI is asking.

Svault is an AI-aware secret access layer. It sits between AI agents and your credentials — enforcing structured requests, detecting suspicious patterns, and making sure the AI actually has a good reason before it touches anything sensitive.

## Install

```bash
curl -fsSL https://svault.soluzy.net/install.sh | bash
```

## Quick Start

```bash
svault init              # set up encrypted vault + passphrase
svault unlock            # start the daemon
svault secret add MY_API_KEY
svault install           # wire into your AI platform (Claude Code, Cursor, etc.)
```

## Status

Early MVP. Local encrypted vault only.

## Docs

Full design: [knowledge base](https://github.com/nim444/Svault/wiki)
