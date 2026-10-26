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

```bash
snyk secrets test --exclude=node_modules,config.json
snyk secrets test --exclude "dist,vendor,temp.log"
```

Only user-provided exclude patterns are applied by this flag.

### Git history

With `--history`, the input path must be a git bundle file instead of a directory. The bundle is uploaded as a new revision (split into parts, so it may exceed the per-file upload limit) and the revision ID is printed. No scan is triggered yet.

```bash
git bundle create repo.bundle --all
snyk secrets test --history repo.bundle
```

## Contributing

This repository is closed to public contributions.
