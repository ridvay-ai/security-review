# Ridvay Security Review 🛡️

Automated security vulnerability analysis for your Pull Requests, powered by **Ridvay AI**.

## How it Works
This Action is a thin wrapper. All the logic (fetching files, LLM analysis, credit management, and posting comments) is handled by the **Ridvay API**. This ensures the action is fast, secure, and provider-agnostic.

## Usage

Add this to your `.github/workflows/security.yml`:

```yaml
name: Security Review

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Ridvay Security Review
        uses: ridvay/security-review@v1
        with:
          ridvay-api-key: ${{ secrets.RIDVAY_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}

```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `ridvay-api-key` | Your Ridvay API Key | Yes | - |
| `github-token` | GitHub token for PR access | Yes | `${{ github.token }}` |
| `ridvay-base-url` | Custom API Base URL | No | `https://api.ridvay.com` |

## Features
- **AI Powered**: Uses state-of-the-art LLMs to find complex security logic flaws.
