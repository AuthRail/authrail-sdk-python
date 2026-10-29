# Releasing

This guide is for maintainers. Public setup remains in the README. The initial
release version is **0.1.0**. Preparing a release does not publish it.

## Check a candidate

After the release preparation has merged, run the **Release** workflow from
`main`, with version `0.1.0` and **publish unchecked**:

```sh
gh workflow run release.yml --ref main -f version=0.1.0 -F publish=false
```

The workflow runs CI, builds the distributions and retains reviewable artifacts
for 14 days. Open its run in Actions, check every job, and download the artifacts.
These artifacts are temporary review downloads, not public releases.

## Before publishing

Complete the connected release checks, confirm the exact main commit and tested
sidecar/SDK combination, and obtain the owner's release approval. Create only
that approved `v0.1.0` tag; never move a published tag. The publish workflow
requires the tag to point to the exact main commit being run. An intervening
main commit requires reviewing the release identity again.

Configure the GitHub environment below with the owner as a required reviewer
and deployment branches restricted to `main`. Publishing is a separate manual
Release workflow run with **publish checked**. A pull request, ordinary push
or check-only run cannot publish.

## PyPI setup

Use GitHub environment **pypi**. In the `authrail` PyPI account, open
**Publishing → Add a new pending publisher** and choose GitHub:

| Field | Value |
| --- | --- |
| PyPI project | `authrail` |
| GitHub owner | `AuthRail` |
| Repository | `authrail-sdk-python` |
| Workflow filename | `release.yml` |
| Environment | `pypi` |

This permits the workflow to create the project on its first authorized publish.
It does not reserve the package name or publish anything immediately. The paid
PyPI organisation is unnecessary. No API token is used.

The publish job downloads the checked wheel/source package, verifies checksums
and uploads those same files through PyPI trusted publishing. Its dependent job
creates the GitHub release with the distributions. If only part of publication
succeeds, inspect the registry and run before retrying; existing distributions
are not silently skipped or replaced.

After publication, install `authrail==0.1.0` in an empty environment and exercise
the connected Runtime flow before updating the public install guide.

[PyPI pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
