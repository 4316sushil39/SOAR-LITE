# SOAR Lite workspace guidance

- Keep this project strictly synthetic and mock-only; do not add integrations or production credentials.
- Every new playbook action must create an impact simulation and wait for explicit human approval.
- Execution and rollback must only update in-memory workflow records and must be recorded in the structured audit log.
- Preserve the test suite's approval-gate and no-external-effects guarantees.
