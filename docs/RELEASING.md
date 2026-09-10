# Releasing agent-trust-broker (ianua-atb)

Releases are **automated through [release-please](https://github.com/googleapis/release-please)**.
You never hand-edit `pyproject.toml` version, `atb.__version__`, gateway
`SERVER_INFO["version"]`, or invent a dated CHANGELOG section on a feature branch.

## One-time setup

1. Settings → Actions → General → Workflow permissions → enable
   **"Allow GitHub Actions to create and approve pull requests"**.
2. Prefer branch protection on `main` that requires PR + CI green.

## Each release

1. Land changes on `main` via PRs titled with
   [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `feat!:` / `BREAKING CHANGE:`).
2. The `release-please` workflow opens or updates a **release PR** that bumps
   versions (including `# x-release-please-version` markers) and `CHANGELOG.md`.
3. **Merge the release PR** when ready — that tags `ianua-atb-vX.Y.Z` and creates
   the GitHub Release.
4. Optional: re-run via Actions → release-please → **Run workflow**.

## Notes

- Manifest: `.release-please-manifest.json` (current: `0.2.0`).
- Config: `release-please-config.json` (`bump-minor-pre-major` for 0.x).
- PyPI Trusted Publishing is not wired yet; this path ships GitHub Releases only.
