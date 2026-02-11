//nolint:testpackage // whitebox testing: access unexported functions and types
package secretstest

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
	mock_secretstest "github.com/snyk/cli-extension-secrets/internal/commands/secretstest/testdata/mocks"
)

// TestObservePathsSentToBackend runs Command.RunWorkflow end-to-end with every
// HTTP call routed through an httptest server. It captures and logs all
// path-like values that would reach the real Snyk backend.
//
// Category A: upload file paths (multipart field names from GAF upload client).
// Category B: root_folder_id from the POST /tests JSON body.
// Bonus: full HTTP request log proving all traffic was intercepted.
func TestObservePathsSentToBackend(t *testing.T) {
	// ── Setup: temp directory with nested text files ─────────────────────
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

	// ── IDs ──────────────────────────────────────────────────────────────
	orgID := uuid.New()
	fakeRevisionID := uuid.New()
	fakeJobID := uuid.New()
	fakeTestID := uuid.New()

	// ── Captured data ────────────────────────────────────────────────────
	var mu sync.Mutex
	var capturedUploadPaths []string
	var capturedTestBody string
	var requestLog []string

	logRequest := func(method, path string) {
		mu.Lock()
		requestLog = append(requestLog, fmt.Sprintf("%s %s", method, path))
		mu.Unlock()
	}

	// ── httptest server: 7 endpoints ─────────────────────────────────────
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logRequest(r.Method, r.URL.Path)

		switch {
		// ── Upload API ───────────────────────────────────────────────────

		// POST /hidden/orgs/{orgID}/upload_revisions → create revision.
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

		// POST .../upload_revisions/{id}/files → upload files (gzip+multipart).
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/files"):
			collectMultipartFieldNames(t, r, &mu, &capturedUploadPaths)
			w.WriteHeader(http.StatusNoContent)

		// PATCH .../upload_revisions/{id} → seal revision.
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

		// ── Test API ─────────────────────────────────────────────────────

		// POST /orgs/{orgID}/tests → start test (capture body).
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			capturedTestBody = string(body)
			mu.Unlock()

			w.Header().Set("Content-Type", "application/vnd.api+json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":   fakeJobID.String(),
					"type": "test_jobs",
					"attributes": map[string]any{
						"status":     "pending",
						"created_at": time.Now().Format(time.RFC3339),
					},
				},
				"jsonapi": map[string]any{"version": "1.0"},
				"links":   map[string]any{},
			})

		// GET /orgs/{orgID}/test_jobs/{jobID} → 303 redirect to test result.
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/test_jobs/"):
			resultPath := fmt.Sprintf("/orgs/%s/tests/%s", orgID, fakeTestID)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			relatedLink := fmt.Sprintf("%s://%s%s", scheme, r.Host, resultPath)

			w.Header().Set("Content-Type", "application/vnd.api+json")
			w.Header().Set("Location", relatedLink)
			w.WriteHeader(http.StatusSeeOther)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":   fakeJobID.String(),
					"type": "test_jobs",
					"attributes": map[string]any{
						"status":     "finished",
						"created_at": time.Now().Format(time.RFC3339),
					},
					"relationships": map[string]any{
						"test": map[string]any{
							"data": map[string]any{
								"id":   fakeTestID.String(),
								"type": "tests",
							},
						},
					},
				},
				"jsonapi": map[string]any{"version": "1.0"},
				"links":   map[string]any{},
			})

		// GET /orgs/{orgID}/tests/{testID} → test result (finished, pass).
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tests/") &&
			!strings.Contains(r.URL.Path, "/findings") &&
			!strings.Contains(r.URL.Path, "/test_jobs/"):
			w.Header().Set("Content-Type", "application/vnd.api+json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":   fakeTestID.String(),
					"type": "tests",
					"attributes": map[string]any{
						"created_at": time.Now().Format(time.RFC3339),
						"state": map[string]any{
							"execution": "finished",
						},
						"outcome": map[string]any{
							"result": "pass",
						},
					},
				},
				"jsonapi": map[string]any{"version": "1.0"},
				"links":   map[string]any{},
			})

		// GET /orgs/{orgID}/tests/{testID}/findings → empty findings.
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/findings"):
			w.Header().Set("Content-Type", "application/vnd.api+json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":    []any{},
				"jsonapi": map[string]any{"version": "1.0"},
				"links":   map[string]any{},
			})

		default:
			t.Logf("UNHANDLED REQUEST: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	// ── Wire real clients ────────────────────────────────────────────────

	// Upload client: real GAF fileupload.Client → httptest.
	uploadClient := fileupload.NewClient(
		srv.Client(),
		fileupload.Config{BaseURL: srv.URL, OrgID: orgID},
	)

	// Test API client: real testapi.TestClient → httptest.
	// Needs a non-redirecting HTTP client (mirrors snykclient behavior).
	noRedirectClient := &http.Client{
		Transport: srv.Client().Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	testClient, err := testapi.NewTestClient(
		srv.URL,
		testapi.WithPollInterval(10*time.Millisecond),
		testapi.WithPollTimeout(5*time.Second),
		testapi.WithCustomHTTPClient(noRedirectClient),
		testapi.WithJitterFunc(func(d time.Duration) time.Duration { return d }),
	)
	require.NoError(t, err)

	// ── Build Command ────────────────────────────────────────────────────

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUI := mock_secretstest.NewMockUserInterface(ctrl)
	mockUI.EXPECT().SetTitle(gomock.Any()).AnyTimes()

	logger := zerolog.Nop()
	rootFolderID, err := computeRelativeInput(nestedDir, tmpDir)
	require.NoError(t, err)

	cmd := &Command{
		Logger:       &logger,
		OrgID:        orgID.String(),
		RootFolderID: rootFolderID,
		RepoURL:      "https://github.com/example/repo",
		Clients: &WorkflowClients{
			FileUpload:  uploadClient,
			TestAPIShim: &testshim.TestAPIClient{TestClient: testClient},
		},
		ErrorFactory:  NewErrorFactory(&logger),
		UserInterface: mockUI,
	}

	// ── Run the full workflow ────────────────────────────────────────────

	mockIctx := mocks.NewMockInvocationContext(ctrl)
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(&url.URL{}).AnyTimes()
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	_, err = cmd.RunWorkflow(ctx, tmpDir)
	require.NoError(t, err)

	// ── Report ───────────────────────────────────────────────────────────

	t.Log("")
	t.Log("═══════════════════════════════════════════════════")
	t.Log("  PATHS SENT TO BACKEND — full E2E observation")
	t.Log("═══════════════════════════════════════════════════")

	t.Log("")
	t.Log("── HTTP request log (proves all traffic intercepted) ──")
	for _, entry := range requestLog {
		t.Logf("  %s", entry)
	}

	t.Log("")
	t.Log("── Category A: Upload file paths (multipart field names) ──")
	for _, p := range capturedUploadPaths {
		flag := ""
		if strings.Contains(p, `\`) {
			flag = " *** BACKSLASH ***"
		}
		t.Logf("  %q%s", p, flag)
	}

	t.Log("")
	t.Log("── Category B: POST /tests body (root_folder_id) ──")
	if capturedTestBody != "" {
		// Pretty-print and extract root_folder_id.
		var parsed map[string]any
		if err := json.Unmarshal([]byte(capturedTestBody), &parsed); err == nil {
			pretty, _ := json.MarshalIndent(parsed, "  ", "  ")
			t.Logf("  full body:\n  %s", string(pretty))
		}
		if strings.Contains(capturedTestBody, `\\`) || strings.Contains(capturedTestBody, `\`) {
			t.Log("  *** POST /tests body contains backslash(es) ***")
		}
	} else {
		t.Log("  WARNING: POST /tests body was not captured")
	}

	t.Log("")
	t.Logf("  computeRelativeInput result: %q", rootFolderID)
	if strings.Contains(rootFolderID, `\`) {
		t.Log("  *** BACKSLASH in RootFolderID ***")
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
