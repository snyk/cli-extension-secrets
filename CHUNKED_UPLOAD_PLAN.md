# Chunked upload plan: git bundles up to ~1 GB

## Goal

Upload a git bundle of up to about 1 GB through the file upload API, which limits each request to 50 MB. The client uploads the bundle in chunks and the server reassembles it.

## Background

- The GAF upload client (`go-application-framework` v0.14.1, `internal/api/fileupload/uploadrevision/client.go`) hard-codes a 50 MB limit per file and 50 MB per request.
- `batchPaths` (GAF `pkg/apiclients/fileupload/batch.go`) groups whole files into requests. It never splits a file, and a file over 50 MB is skipped with `FileSizeLimitError`.
- This repo's `FileSizeFilter` (`pkg/filefilter/file_size.go`) drops files over 1 MB, and the text-only filter would drop a binary bundle.
- The current flow is: create revision, upload batches, seal revision, then trigger the scan with the revision ID (`internal/commands/secretstest/command.go`).
- The upload API has no chunked or append support today.

## Decisions so far

- The API will be extended to accept chunks, and the server will reassemble them.
- The upper bound to design for is about 1 GB.
- The change goes in GAF as a separate code path and a separate workflow, so other extensions are unaffected.
- The input is a git bundle (binary, already compressed).

## Where chunking happens

Chunking happens on the client, in GAF, in a new chunked-upload method. It is not in this repo and not on the server.

| Component | Responsibility |
|---|---|
| This repo | Passes GAF the path of the bundle, plus org and revision. Knows nothing about chunk size or boundaries. |
| GAF (`pkg/apiclients/fileupload`, new method) | Stats the file, computes `ceil(size / chunkSize)`, calls "start", sends each chunk, calls "complete". |
| Server | Receives numbered chunks and reassembles them. Never decides how the file is split. |

GAF reads each chunk with `io.SectionReader(file, offset, chunkSize)` and sends it as a request body. Nothing is copied into a large buffer, so memory stays at about one chunk per in-flight request.

The client chooses the chunk size, below the server's per-request limit. A value of 32-40 MB leaves room for the multipart envelope. Ideally the "start" response returns the maximum chunk size so the client does not hard-code 50 MB.

GAF currently gzips every request body. A git bundle is already compressed, so gzip costs CPU and saves almost nothing. The chunked path should skip it. The per-request uncompressed-size limit then applies to the chunk size, not to the 1 GB file.

## Plan

### 1. Define the chunked-upload contract (API, with the upload API owners)

A minimal design:

- **Start:** create a chunked file in a revision. The request gives the path, total size, chunk size and optionally a checksum. The response returns an upload ID.
- **Send:** upload chunk N for that upload ID. This is idempotent, so a retry is safe. Each chunk is at most 50 MB.
- **Complete:** the server checks that all chunks are present and that the size and checksum match, assembles the file, and makes it a normal file in the revision.
- **Seal:** the existing step, unchanged.

Open API choices: how long unfinished uploads are kept before cleanup, and whether chunks can be sent in parallel.

### 2. GAF: a separate chunked-upload path

- Add a new client method such as `UploadLargeFile`, alongside `CreateRevisionFromChan`. The existing batching client stays untouched.
- Read chunks with `io.SectionReader`.
- Add per-chunk retries with backoff, a small parallelism cap (2-4), context cancellation, and a progress callback.
- Compute a SHA-256 of the whole file for the server-side integrity check.

### 3. This repo: a separate workflow for bundles

- Create the bundle with `git bundle create` into a temp file, or accept a path to an existing bundle. Clean up the temp file afterwards.
- Skip the 1 MB size filter and the text-only filter on this workflow. The existing `secrets.test` filtering is unchanged.
- Call the new GAF method, then seal, then trigger the scan with the revision ID as today.
- Replace the 30 s `FilterAndUploadFilesTimeout` with a timeout suited to large uploads, and show progress.
- Add error mapping for chunk failures in `internal/commands/secretstest/errors.go`.
- Add metrics for size, chunk count and upload time in `internal/instrumentation/`.
- Bump the GAF version in `go.mod`.

### 4. Server side (scanner, outside this repo)

The scanner has to unbundle the file and scan its contents. The end-to-end result depends on this.

### 5. Rollout and testing

- Unit tests for chunk boundaries (exact multiple, one byte over, tiny file) and for retry and resume.
- A memory test with a large sparse file.
- An end-to-end test against a test org with a bundle of several hundred MB.
- Put the new workflow behind a feature flag until the API is live.

## Order of work

API contract, then the server side, then GAF, then this repo. GAF and this repo can use a fake client until the API exists.

## Open questions

1. Is the "separate workflow" a new command or flag (for example `snyk secrets test --git-history`), or an internal workflow ID?
2. Who creates the bundle: the CLI at run time, or the user?
3. Should an interrupted upload resume? Resuming means the client can ask the server which chunks it already has, which adds one more API endpoint.
