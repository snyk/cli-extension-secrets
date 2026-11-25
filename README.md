<p align="center">
  <img src="https://snyk.io/style/asset/logo/snyk-print.svg" />
</p>

# Snyk Secrets Test CLI Extension

## Overview

This module implements the Snyk CLI Extension for Secrets workflows.

## Workflows

- `snyk secrets test`

### Excluding files and directories

You can exclude files or directories from secrets scans using the `--exclude` flag. This performs **basename matching**, excluding the specified names anywhere they appear in the project tree.

**Note: Paths containing slashes (`/` or `\`) are not allowed.**
**Note: `--exclude` cannot be combined with `--history`.**

```bash
snyk secrets test --exclude=node_modules,config.json
snyk secrets test --exclude "dist,vendor,temp.log"
```

Only user-provided exclude patterns are applied by this flag.

### Scanning git history

By default, `snyk secrets test` scans the files in the working tree. Use the `--history` flag to scan the repository's full git history instead, so that secrets that were committed and later removed are found too.

```bash
snyk secrets test --history
```

How it works:

1. The repository is cloned into a temporary directory, repacked, and packaged into a single git bundle containing all refs.
2. The bundle is uploaded and scanned. The temporary directory is removed when the command finishes.

Requirements and limitations:

- `git` must be installed and available on your `PATH`.
- The input path must be inside a git repository.
- `--history` cannot be combined with `--report`, because history scans are stateless and cannot be shared with the Snyk Web UI.
- `--history` cannot be combined with `--exclude`, as the whole git repo is packaged and scanned
- Git history scanning is gated behind a feature flag. If it is not enabled for your organization, the command fails with "Git history scanning is not yet supported."
- Large repositories take longer, and need enough free disk space in the temporary directory for the clone and the bundle. The temporary directory follows the Snyk CLI temp directory setting.

## Contributing

This repository is closed to public contributions.
