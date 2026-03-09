package secretstest

import (
	"bytes"
	"os"

	"github.com/rs/zerolog"
)

// normalizeLineEndings consumes file paths from in, strips any \r\n -> \n
// in-place, and forwards the original path. On Unix this is a no-op (files
// never contain \r\n). On Windows with git autocrlf=true, this undoes the
// CRLF conversion so the backend scanner receives identical bytes regardless
// of the client OS. The in-place write is safe because git will re-apply
// autocrlf on the next checkout.
func normalizeLineEndings(in <-chan string, logger *zerolog.Logger) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		for path := range in {
			if err := stripCRLF(path); err != nil {
				logger.Warn().Err(err).Str("path", path).Msg("failed to normalize line endings, uploading as-is")
			}
			out <- path
		}
	}()
	return out
}

// stripCRLF rewrites path in-place with \r\n replaced by \n.
// If the file contains no \r\n, no write occurs.
func stripCRLF(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if !bytes.Contains(raw, []byte("\r\n")) {
		return nil
	}

	normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	return os.WriteFile(path, normalized, 0o644)
}
