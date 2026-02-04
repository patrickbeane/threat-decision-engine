# CrowdSec Enforcement Wrapper

This wrapper provides a **safe, limited interface** to `cscli decisions` for the threat-decision-engine. It runs with elevated privileges via sudo but restricts operations to only `ban` and `delete` actions with validated inputs.

## Installation

1. **Copy the wrapper to system path:**
```bash
sudo cp crowdsec-enforce /usr/bin/crowdsec-enforce
sudo chown root:root /usr/bin/crowdsec-enforce
sudo chmod 755 /usr/bin/crowdsec-enforce
```

2. **Configure sudoers** by creating `/etc/sudoers.d/crowdsec-enforce`:
```
# CrowdSec enforcement wrapper for threat-decision-engine
youruser ALL=(root) NOPASSWD: /usr/bin/crowdsec-enforce *
```

Replace `youruser` with the account running the threat-decision-engine.

3. **Validate sudoers syntax:**
```bash
sudo visudo -c
```

## Usage

### Automated (via threat-engine)
The wrapper is called automatically when running:
```bash
threat-engine --input https://threats.beane.me/api --mode enforce --yes
```

### Manual
```bash
# Ban an IP for 12 hours
sudo /usr/bin/crowdsec-enforce ban 192.168.1.100 12h "brute-force"

# Ban with default reason
sudo /usr/bin/crowdsec-enforce ban 10.0.0.50 24h

# Permanent ban (converts to 14d internally)
sudo /usr/bin/crowdsec-enforce ban 203.0.113.5 perm "malicious-actor"

# Remove a ban
sudo /usr/bin/crowdsec-enforce delete 192.168.1.100
```

## Security Design

**Allowed operations:**
- `ban <ip> <duration> [reason]` - Add a CrowdSec decision
- `delete <ip>` - Remove a CrowdSec decision

**Safety guarantees:**
- No shell expansion of user input (uses `exec` to prevent injection)
- No network access required
- No arbitrary `cscli` commands allowed
- Input validation on all parameters
- Runs as root only for the minimal `cscli` operations needed

**Duration formats:**
- `12h`, `7d`, `30d` - Standard durations
- `perm` - Converted to `14d` (maximum for permanent bans)

> **Note**: : Permanent bans are capped at 14 days to account for common IP rotation and to keep the decision database manageable.

## Integration

Called by `threat_engine/enforce.py`:
```python
subprocess.run(
    ["sudo", WRAPPER, "ban", ip, duration, reason],
    check=True,
)
```

The wrapper is located at `/usr/bin/crowdsec-enforce` and must be executable by the threat-engine service user via passwordless sudo.
