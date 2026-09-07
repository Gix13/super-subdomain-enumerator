# Contributing

Contributions are welcome when they improve reliability, portability, documentation, or safe evidence handling.

## Pull-request checklist

1. Discuss substantial integration or workflow changes in an issue first.
2. Use mocks, synthetic fixtures, or systems you own for tests.
3. Never commit credentials, targets, captures, callbacks, browser state, or scan results.
4. Preserve the passive/active boundary and make network side effects explicit.
5. Run `python -m unittest discover -s tests -v` and `node --check crawlee/crawler.js`.
6. Document new executables, environment variables, output artifacts, and failure modes.

Changes intended to bypass provider controls, conceal activity, or weaken authorization safeguards will not be accepted.
