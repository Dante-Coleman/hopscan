# hopscan

Email header and phishing analyzer. Python CLI, entry point `hopscan.py`, logic in `core/`.

## Git
- Always push to `main`. Commit finished work on `main` and push it to `origin main`; don't leave work on other branches.

## Layout
- `core/parser.py` - headers and Received hops
- `core/analyzer.py` - Authentication-Results parsing, alignment, auth scoring, verdict
- `core/content.py` - static body/link/attachment extraction (never fetches or opens anything)
- `core/heuristics.py` - phishing checks; `core/brands.py` - impersonated brands and their real domains
- `core/scoring.py` - point value of every finding
- `tests/` - pytest suite; sample emails in `tests/fixtures/`

## Testing
- `python -m pytest` must pass before pushing.
- Add a fixture-based test for every new detection rule or bug fix.
