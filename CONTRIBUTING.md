# Contributing

## Quality bar

- `ruff check .` clean (rules E, F, I, UP, B, S, SIM)
- `mypy sbom_overlay` strict, clean
- `pytest --cov=sbom_overlay --cov-branch` 100% line + branch coverage
- `bandit -c pyproject.toml -r sbom_overlay` clean

The bar mirrors `sbom-sentinel`. Coverage gate ratchets up; do not lower it.

## Workflow

- Branch from `main`, open a PR, let CI run.
- Squash-merge. Conventional-ish commit messages (`feat:`, `fix:`, `docs:`, ...).
- Don't add features beyond the task. Three similar lines is better than a
  premature abstraction.

## Output format

ASCII only in user-facing strings: `[+]`, `[-]`, `[!]`, `[i]`. No emojis.
