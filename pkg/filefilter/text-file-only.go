package filefilter

import "bytes"

const (
	// _MIN_NULLS_FOR_UTF_16_HEURISTIC is the minimum number of nulls needed to trust the pattern
	// A single stray null byte isn't a pattern
	_MIN_NULLS_FOR_UTF_16_HEURISTIC = 4
	// _FILE_HEADER_SAMPLE_SIZE is the number of bytes read from a file in order to
	// determine if it's text or binary
	_FILE_HEADER_SAMPLE_SIZE = 512
	// _UTF_16_PATTERN_THRESHOLD is how strong the pattern must be (e.g., 0.9 = 90%)
	// 90% of nulls must be on *either* even or odd indices to be considered UTF-16
	_UTF_16_PATTERN_THRESHOLD = 0.90
)

// BOM(Byte Order Mark) definitions
var (
	bomUTF16LE = []byte{0xFF, 0xFE}
	bomUTF16BE = []byte{0xFE, 0xFF}
)

type textFileOnly struct {
}

func TextFileOnlyFilter() FileFilter {
	return &textFileOnly{}
}

func (textFileOnly) FilterOut(file LocalFile) bool {
	// Attempt to read the file header
	header, err := file.ReadHeader(_FILE_HEADER_SAMPLE_SIZE)
	if err != nil {
		// TODO: log the error
		// Filters are enforced, we should exclude any files that we can't classify
		// because of missing file header
		return true
	}
	return !IsTextContent(header)
}

// IsTextContent determines if the data slice contains text content
// based on the null byte method. See: https://docs.google.com/document/d/1GYir_j0ITTxg_CqyAw8BeUZYCCUyNMAePbGw5nsTGYE/
func IsTextContent(data []byte) bool {
	// Empty files are considered text
	if len(data) == 0 {
		return true
	}
	// Fast path for common text files (no nulls)
	if bytes.IndexByte(data, 0x00) == -1 {
		return true
	}

	// Nulls ARE present from this point on
	// Check for definitive text BOMs
	if isText, _ := checkBOM(data); isText {
		return true
	}

	// No BOM. Run the null-pattern heuristic to check for UTF-16
	// If the check fails, it's binary (sparse or random nulls)
	isText, _ := checkUTF16Heuristic(data)
	return isText
}

// Helper functions
// checkBOM looks for known Unicode Byte Order Marks that signify text
func checkBOM(header []byte) (isText bool, reason string) {
	if bytes.HasPrefix(header, bomUTF16LE) {
		return true, "utf-16-le-bom"
	}
	if bytes.HasPrefix(header, bomUTF16BE) {
		return true, "utf-16-be-bom"
	}
	return false, ""
}

// checkUTF16Heuristic analyzes the *pattern* of null bytes to guess if it's UTF-16
// It returns (isText, reason). If isText is false, the reason explains why it's
// classified as binary (e.g., "has-null-random")
func checkUTF16Heuristic(header []byte) (isText bool, reason string) {
	var oddNulls, evenNulls, totalNulls int

	// Count nulls at even vs. odd indices
	for i, b := range header {
		if b != 0x00 {
			continue
		}

		totalNulls++
		if i%2 == 0 {
			evenNulls++
		} else {
			oddNulls++
		}
	}
	// Check if we have enough data to make a guess
	if totalNulls < _MIN_NULLS_FOR_UTF_16_HEURISTIC {
		// Not enough nulls for a pattern. Safer to assume binary
		return false, "has-null-sparse"
	}

	// Calculate the pattern strength
	evenShare := float64(evenNulls) / float64(totalNulls)
	oddShare := float64(oddNulls) / float64(totalNulls)

	// Check if the pattern is strong enough
	if evenShare > _UTF_16_PATTERN_THRESHOLD || oddShare > _UTF_16_PATTERN_THRESHOLD {
		// >90% of nulls are on one side. This is a strong UTF-16 signal
		return true, "utf-16-heuristic"
	}
	// Default: Nulls are present but scattered randomly
	return false, "has-null-random"
}
