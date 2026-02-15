# SSH Vault Skill

This skill enables secure SSH access through a Passkey-protected vault.

## Overview

SSH Vault MCP provides secure, human-approved SSH access. The vault stores encrypted credentials and requires Passkey authentication to unlock.

## Workflow

### 1. Check Vault Status

```json
{ "tool": "vault_status" }
```

Returns:
- `locked: true` - Need to unlock first
- `locked: false` - Ready to use

### 2. Unlock Vault (if locked)

```json
{ "tool": "request_unlock" }
```

Returns:
```json
{
  "status": "pending",
  "unlockUrl": "https://vault.example.com/sign?challenge=abc123",
  "listenUrl": "https://vault.example.com/api/challenge/abc123/listen",
  "message": "Please visit the URL and authenticate with your Passkey."
}
```

**Action**: Show the URL to the user and ask them to authenticate.

**Two ways to complete:**

**Option A: Automatic notification (preferred)**
- Connect to `listenUrl` via SSE
- Wait for `{ type: "approved" }` event
- Continue automatically

**Option B: Manual code**
- User copies unlock code from web page
- Submit with: `{ "tool": "submit_unlock", "unlock_code": "UNLOCK-X7K9P" }`

### 3. List Available Hosts

```json
{ "tool": "list_hosts", "filter": "dev-*" }
```

### 4. Execute Commands

```json
{
  "tool": "execute_command",
  "host": "dev-server-01",
  "command": "ls -la /var/log"
}
```

**If command needs approval** (outside your allowed commands):
```json
{
  "needsApproval": true,
  "approvalUrl": "https://vault.example.com/approve?challenge=xyz",
  "message": "This command requires approval."
}
```

Ask user to visit the approval URL, get the unlock code, and submit it.

### 5. End Session

```json
{ "tool": "revoke_session" }
```

## Important Notes

1. **Don't block on approval** - When waiting for user approval, inform them and continue with other tasks.

2. **Session expiration** - Sessions expire after a timeout. If commands fail, check vault status.

3. **Policy limits** - Some commands may be denied. Check the error message for details.

4. **Dangerous commands** - Commands like `rm -rf /` are automatically blocked.

## Example Conversation

```
User: Check the logs on dev-server-01

Agent: Let me access the SSH vault first.
[calls vault_status]
The vault is locked. Please visit this URL to unlock:
https://vault.example.com/sign?challenge=abc123

User: Done, code is UNLOCK-X7K9P

Agent: [calls submit_unlock with code]
Vault unlocked. Now let me check the logs.
[calls execute_command: tail -100 /var/log/syslog]
Here are the recent logs: ...
```

## Error Handling

| Error | Action |
|-------|--------|
| "Vault is locked" | Call request_unlock |
| "Session expired" | Call request_unlock again |
| "Command denied" | Inform user, suggest alternative |
| "Host not found" | Call list_hosts to show available options |
| "Needs approval" | Show approval URL to user |
