//nolint:testpackage // whitebox testing: access unexported computeRelativeInput and createTestResource
package secretstest

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/stretchr/testify/require"
)

// TestObservePathsSentToBackend is an observation test that intercepts all
// path-like values that the extension would send to the backend.
//
// It does NOT assert or fail on backslashes. Instead it logs every path and
// flags which ones contain backslashes, so CI output on Windows reveals exactly
// what needs fixing.
//
// Category A: upload file paths (multipart field names from GAF upload client).
// Category B: RootFolderID (from computeRelativeInput + createTestResource).
func TestObservePathsSentToBackend(t *testing.T) {
	// ── Setup: temp directory with nested files ──────────────────────────
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "src", "subdir")
	require.NoError(t, os.MkdirAll(nestedDir, 0o755))

	filesToCreate := []string{
		filepath.Join(tmpDir, "root.go"),
		filepath.Join(tmpDir, "src", "main.go"),
		filepath.Join(nestedDir, "helper.go"),
	}
	for _, f := range filesToCreate {
		require.NoError(t, os.WriteFile(f, []byte("package main\n"), 0o600))
	}

	// ── Track intercepted paths ──────────────────────────────────────────
	var mu sync.Mutex
	var capturedUploadPaths []string
	fakeRevisionID := uuid.New()

	// ── httptest server mimicking the Snyk upload API ────────────────────
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// POST /hidden/orgs/{orgID}/upload_revisions → create revision
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/upload_revisions"):
			w.Header().Set("Content-Type", "application/vnd.api+json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":   fakeRevisionID.String(),
					"type": "upload_revision",
					"attributes": map[string]any{
						"revision_type": "snapshot",
						"sealed":        false,
					},
				},
			})

		// POST .../upload_revisions/{id}/files → upload files (gzip + multipart)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/files"):
			collectMultipartFieldNames(t, r, &mu, &capturedUploadPaths)
			w.WriteHeader(http.StatusNoContent)

		// PATCH .../upload_revisions/{id} → seal revision
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/upload_revisions/"):
			w.Header().Set("Content-Type", "application/vnd.api+json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":   fakeRevisionID.String(),
					"type": "upload_revision",
					"attributes": map[string]any{
						"revision_type": "snapshot",
						"sealed":        true,
					},
				},
			})

		default:
			t.Logf("UNHANDLED REQUEST: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	// ── Category A: Upload file paths via real GAF upload client ─────────
	orgID := uuid.New()
	cfg := fileupload.Config{BaseURL: srv.URL, OrgID: orgID}
	uploadClient := fileupload.NewClient(srv.Client(), cfg)

	pathsChan := make(chan string, len(filesToCreate))
	for _, f := range filesToCreate {
		pathsChan <- f
	}
	close(pathsChan)

	result, err := uploadClient.CreateRevisionFromChan(t.Context(), pathsChan, tmpDir)
	require.NoError(t, err)

	// ── Category B: RootFolderID ─────────────────────────────────────────
	rootFolderID, err := computeRelativeInput(nestedDir, tmpDir)
	require.NoError(t, err)

	testResource, err := createTestResource(
		fakeRevisionID.String(),
		"https://github.com/example/repo",
		rootFolderID,
	)
	require.NoError(t, err)

	// ── Report ───────────────────────────────────────────────────────────
	t.Log("")
	t.Log("═══════════════════════════════════════════════════")
	t.Log("  PATHS SENT TO BACKEND — observation report")
	t.Log("═══════════════════════════════════════════════════")

	t.Log("")
	t.Log("── Category A: Upload file paths (multipart field names) ──")
	for _, p := range capturedUploadPaths {
		flag := ""
		if strings.Contains(p, `\`) {
			flag = " *** BACKSLASH ***"
		}
		t.Logf("  %q%s", p, flag)
	}
	t.Logf("  uploaded: %d  skipped: %d", result.UploadedFilesCount, len(result.SkippedFiles))

	t.Log("")
	t.Log("── Category B: RootFolderID ──")
	flagB := ""
	if strings.Contains(rootFolderID, `\`) {
		flagB = " *** BACKSLASH ***"
	}
	t.Logf("  computeRelativeInput: %q%s", rootFolderID, flagB)

	resourceJSON, _ := json.MarshalIndent(testResource, "  ", "  ")
	t.Logf("  test resource payload:\n  %s", string(resourceJSON))
	if strings.Contains(string(resourceJSON), `\`) {
		t.Log("  *** test resource JSON contains backslash(es) ***")
	}

	t.Log("")
	t.Log("═══════════════════════════════════════════════════")
}

// collectMultipartFieldNames decompresses the gzip body, parses the multipart
// form, and appends every field name (= relative file path) to dst.
func collectMultipartFieldNames(t *testing.T, r *http.Request, mu *sync.Mutex, dst *[]string) {
	t.Helper()

	gzReader, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Logf("ERROR: gzip.NewReader: %v", err)
		return
	}
	defer gzReader.Close()

	ct := r.Header.Get("Content-Type")
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Logf("ERROR: ParseMediaType(%q): %v", ct, err)
		return
	}

	mr := multipart.NewReader(gzReader, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Logf("ERROR: NextPart: %v", err)
			break
		}
		fieldName := part.FormName()
		// Drain the part so the reader can advance.
		_, _ = io.Copy(io.Discard, part)
		part.Close()

		mu.Lock()
		*dst = append(*dst, fieldName)
		mu.Unlock()
	}
}
