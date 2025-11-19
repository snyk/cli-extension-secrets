package filefilter

import "sync"

type FileFilter interface {
	FilterOut(path string) bool
}

// Filter runs the provided files through the filters concurrently.
func Filter(files chan string, maxThreadCount int, filters ...FileFilter) chan string {
	filteredFiles := make(chan string, maxThreadCount)

	var wg sync.WaitGroup
	for range maxThreadCount {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Iterate over incoming paths from the walker
			for path := range files {
				keep := true
				// Check all filters (stop at first failure)
				for _, filter := range filters {
					if filter.FilterOut(path) {
						keep = false
						break
					}
				}

				if keep {
					filteredFiles <- path
				}
			}
		}()
	}

	// This closer routine waits for workers to finish, then closes the channel.
	// It does not block the return of this function.
	go func() {
		wg.Wait()
		close(filteredFiles)
	}()
	return filteredFiles
}
