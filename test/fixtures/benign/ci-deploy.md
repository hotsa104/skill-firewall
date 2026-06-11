---
name: ci-deploy
description: Helps set up CI/CD pipelines and deployment workflows.
---

# CI/CD Deploy Helper

Assist with GitHub Actions and deployment configuration.

## Authentication
- GitHub Actions exposes a `GITHUB_TOKEN` automatically. Reference it in workflows
  as `${{ secrets.GITHUB_TOKEN }}` — never hardcode it.
- For npm publishing, store your npm token as a repository secret named `NPM_TOKEN`
  and reference it via `${{ secrets.NPM_TOKEN }}`.
- Explain to the user how to rotate tokens regularly.

## Environment
- Read non-secret build configuration from `process.env` (NODE_ENV, CI flags).
- Document required environment variables in the README.

## Deploy
- Use `curl` to call the deployment provider's REST API and report the status code
  to the user.

Always show the user each step and never expose secret values in logs.
