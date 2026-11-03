## Summary

The agents playbook action bridge now reads `CORE_API_URL`, matching the variable set on the agents service in `docker-compose.yml`, with `API_SERVICE_URL` and `API_URL` kept as fallbacks.

## Type of change

- [x] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Refactor / tech debt
- [ ] CI / infra change

## Related issues

## Changes

- `services/agents/app/playbook/action_bridge.py`: prefer `CORE_API_URL` when resolving the API base for playbook step dispatch.
- `services/agents/tests/test_action_bridge_core_api_url.py`: regression test via real `dispatch_step` HTTP path (respx).

## Testing

- [x] Unit tests added / updated
- [x] Integration tests pass locally
- [ ] Manually tested (describe steps below)

<details>
<summary>Manual test steps</summary>

1. `cd services/agents && pytest tests/test_action_bridge_core_api_url.py -q`
2. Full agents suite: `pytest -q` (2456 passed locally)

</details>

## Screenshots (if UI changes)

N/A

## Checklist

- [x] My code follows the style guidelines of this project (`ruff`, `eslint`, `gofmt`)
- [x] I have performed a self-review of my own code
- [x] I have added tests that prove my fix is effective or that my feature works
- [x] New and existing unit tests pass locally
- [ ] I have updated documentation as needed (README, CHANGELOG, CONTRIBUTING)
- [x] My changes do not introduce new linter warnings
- [x] I have checked for sensitive data / credentials in my diff

## Eval harness (required for substrate / playbook / detection changes)

- [x] Not applicable — this PR does not touch substrate, playbooks, detections, or eval inputs
- [ ] No axis regressed
- [ ] An axis regressed; rationale and follow-up are described in the Summary above
