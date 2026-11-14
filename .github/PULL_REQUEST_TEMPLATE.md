## Summary

<!-- What changed and why? -->

## Checklist

- [ ] `pytest -q -m "not relay"` passes locally
- [ ] Relay E2E passes locally or in CI when the change touches transport/relay
- [ ] `python -m pyflakes ...` (see CI lint scope) is clean
- [ ] `python scripts/verify_package.py` passes for packaging changes
- [ ] No secrets, packet captures or machine-local paths are committed
- [ ] Documentation/comments are updated when behaviour changes

## Testing

<!-- Commands, environments (OS/Python), and relevant output. -->

## Related issues

<!-- Fixes #... -->
