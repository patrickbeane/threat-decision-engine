# Enforcement Wrappers

Scripts in this directory are executed with elevated privileges via sudo.

Rules:
- No network access
- No dynamic paths
- No shell expansion of user input
- One purpose per wrapper

These scripts translate threat-engine decisions into enforcement actions.
