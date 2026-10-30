# Releasing

This guide is for maintainers. Public installation instructions are in the README.
The coordinated documentation refresh targets **0.1.1**; published versions are
immutable, so never move a released tag or replace an existing package.

## Check a candidate

Run the **Release** workflow from `main` with publishing disabled:

```sh
gh workflow run release.yml --ref main -f version=0.1.1 -F publish=false
```

The workflow runs CI and builds reviewable artifacts, retained for 14 days.
Inspect the run and download its artifacts. Checksum files accompany them.
These temporary artifacts are not registry releases.

## Publish a checked version

Confirm the release commit and tested SDK/sidecar combination, and create the
matching `v0.1.1` tag at that exact main commit. The workflow rejects a missing or
mismatched tag. Its publishing environment allows only `main`.

```sh
gh workflow run release.yml --ref main -f version=0.1.1 -F publish=true
```

An explicit publish run automatically follows successful CI with publishing.
There is no additional GitHub reviewer approval. Pull requests, ordinary pushes
and check-only runs do not publish. Inspect both registry availability and the
GitHub release afterward; do not blindly repeat a partially completed upload.

## PyPI

Project: [authrail](https://pypi.org/project/authrail/).
GitHub environment: **pypi**. The project uses this GitHub trusted publisher:

| Field | Value |
| --- | --- |
| Project | `authrail` |
| GitHub owner | `AuthRail` |
| Repository | `authrail-sdk-python` |
| Workflow | `release.yml` |
| Environment | `pypi` |

The upload uses OIDC, not a stored API token. The job verifies checksums and
publishes the checked wheel/source distribution, then creates its GitHub release.
Existing distributions are not silently skipped or replaced. If only part of
publication succeeds, inspect the run and registry before retrying.

After publication, verify `python -m pip install authrail==0.1.1` in an empty
virtual environment and exercise the connected Runtime flow.

[PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/)
