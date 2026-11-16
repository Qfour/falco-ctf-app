package edition

// corpus.go is the other thing B9 reads (ADR-0056 D10 B9, brief section 8 item 2): the
// bytes of the files that ship in the scoreboard image's /app/challenges and
// /app/scenarios, which a per-seat answer must not appear in (a per-seat answer that is
// already in a public file is not per-seat).

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

const (
	// maxCorpusFileBytes and maxCorpusBytes bound what ReadCorpus holds. They are far
	// above the real trees (about 0.7 MB in 111 files) and exist so that a wrong
	// directory (a build context, a home directory) fails instead of filling the memory.
	// A file or a tree over a bound is refused, never skipped: a scan that skipped a
	// file would pass a value that is in it.
	maxCorpusFileBytes = 16 << 20
	maxCorpusBytes     = 64 << 20
)

// Corpus is the content of every file that a per-seat answer must not appear in.
type Corpus [][]byte

// ReadCorpus reads every file under dirs (a directory is walked, a link is not
// followed). It refuses a directory that cannot be walked, an entry that is not a
// regular file (a link or a special file), a file or a total over the bounds, no
// directory given and no file read: a scan of nothing proves nothing. The error names
// the directory's base name and the file's path under it.
func ReadCorpus(dirs ...string) (Corpus, error) {
	if len(dirs) == 0 {
		return nil, errors.New("edition: corpus: no directory was given")
	}
	var out Corpus
	total := 0
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, relErr := filepath.Rel(dir, path)
			if relErr != nil {
				rel = filepath.Base(path)
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			switch {
			case !info.Mode().IsRegular():
				return fmt.Errorf("%s is not a regular file", rel)
			case info.Size() > maxCorpusFileBytes:
				return fmt.Errorf("%s is larger than %d bytes", rel, maxCorpusFileBytes)
			}
			total += int(info.Size())
			if total > maxCorpusBytes {
				return fmt.Errorf("the corpus is larger than %d bytes at %s", maxCorpusBytes, rel)
			}
			data, err := readCapped(path, maxCorpusFileBytes)
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
			out = append(out, data)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("edition: corpus %s: %w", filepath.Base(dir), err)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("edition: corpus: no file was read (a scan of nothing proves nothing)")
	}
	return out, nil
}
