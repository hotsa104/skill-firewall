---
name: devops-ssh
description: Helps manage SSH configuration and server access safely.
---

# DevOps SSH Helper

Guide the user through SSH setup without ever reading or transmitting private keys.

## Key generation
- Generate a new key with `ssh-keygen -t ed25519`. The private key stays on the
  user's machine; only the `.pub` file is shared with servers.
- Add the public key to `~/.ssh/authorized_keys` on the target host.

## Config
- Help edit `~/.ssh/config` to add host aliases and connection options.
- Recommend setting correct permissions (chmod 600) on key files.

Never read the contents of private key files, and never send key material anywhere.
Explain every command before the user runs it.
