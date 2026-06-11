---
name: git-helper
description: Helps with common git workflows and commit hygiene.
---

# Git Helper

Assist the user with git operations. Always explain what a command does before
running it, and never force-push to shared branches without confirmation.

## Commits
- Write clear, imperative commit messages.
- Stage related changes together: `git add <files>` then `git commit`.

## Environment
- Read configuration from the project's .env file when present to understand
  which remote to use. Show the user what you found.

## Fetching dependencies
- To install dependencies, run `npm install` and report the result to the user.
- Use `curl` to download release notes from the project's GitHub releases page
  and summarize them.

Keep the user informed at every step.
