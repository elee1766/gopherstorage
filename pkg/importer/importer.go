package importer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
)

type Existing string

const (
	ExistingSkip    Existing = "skip"
	ExistingError   Existing = "error"
	ExistingReplace Existing = "replace"
)

type Options struct {
	Prefix           string
	Existing         Existing
	Workers          int
	DryRun           bool
	MaxDocumentBytes int64
	AllowPublic      bool
	Progress         func(Event)
}

type Event struct {
	Path   string
	Action string
	Bytes  int64
	Err    error
}

type Result struct {
	Imported    int64
	Planned     int64
	Skipped     int64
	Unsupported int64
	Failed      int64
	Bytes       int64
}

const (
	ActionImported    = "imported"
	ActionPlanned     = "planned"
	ActionSkipped     = "skipped"
	ActionUnsupported = "unsupported"
	ActionFailed      = "failed"
	maxPathBytes      = 4096
	maxPathSlashes    = 65
	maxDepth          = 64
	readBatch         = 256
	operationTimeout  = 5 * time.Minute
)

var errUnsupportedPlatform = errors.New("directory import requires Linux secure file traversal")

type job struct {
	rel  string
	path string
}
type outcome struct {
	event Event
	stop  bool
}

type eventEmitter struct {
	fn func(Event)
}

func (e *eventEmitter) emit(ev Event) {
	if e.fn != nil {
		e.fn(ev)
	}
}

func (o Options) Validate() error {
	if o.Prefix == "" {
		o.Prefix = "/"
	}
	if err := validateFolderPath(o.Prefix); err != nil {
		return fmt.Errorf("invalid prefix: %w", err)
	}
	if !o.AllowPublic && (o.Prefix == "/public/" || strings.HasPrefix(o.Prefix, "/public/")) {
		return errors.New("public destination requires AllowPublic")
	}
	if o.Existing == "" {
		o.Existing = ExistingSkip
	}
	if o.Existing != ExistingSkip && o.Existing != ExistingError && o.Existing != ExistingReplace {
		return fmt.Errorf("invalid existing policy %q", o.Existing)
	}
	if o.Workers < 0 || o.Workers > 64 {
		return errors.New("worker count must be between 0 and 64")
	}
	if o.MaxDocumentBytes < 0 {
		return errors.New("negative maximum document size")
	}
	return nil
}

// Run imports regular files below source. The source tree must remain unchanged
// for the duration of the run; the importer does not provide snapshot semantics.
func Run(ctx context.Context, source string, backend rsserver.StorageBackend, opts Options) (Result, error) {
	src, err := OpenSource(source)
	if err != nil {
		return Result{}, err
	}
	defer src.Close()
	return RunSource(ctx, src, backend, opts)
}

// RunSource imports regular files from an already-open source directory.
func RunSource(ctx context.Context, source *Source, backend rsserver.StorageBackend, opts Options) (Result, error) {
	var result Result
	if backend == nil {
		return result, errors.New("nil storage backend")
	}
	if source == nil {
		return result, errors.New("nil import source")
	}
	if err := opts.Validate(); err != nil {
		return result, err
	}
	if opts.Prefix == "" {
		opts.Prefix = "/"
	}
	if opts.Existing == "" {
		opts.Existing = ExistingSkip
	}
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if ctx == nil {
		ctx = context.Background()
	}
	root, sourcePath, err := source.cloneRoot()
	if err != nil {
		return result, err
	}
	defer root.close()
	emitter := &eventEmitter{fn: opts.Progress}
	jobs := make(chan job, opts.Workers*2)
	results := make(chan outcome, opts.Workers*2)
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				out := process(workerCtx, root, backend, j, opts)
				results <- out
				if out.stop {
					cancel()
				}
			}
		}()
	}
	walkDone := make(chan error, 1)
	go func() {
		err := root.walk(workerCtx, jobs, opts.Prefix, results)
		if err != nil {
			results <- outcome{event: Event{Path: sourcePath, Action: ActionFailed, Err: err}, stop: true}
			cancel()
		}
		close(jobs)
		walkDone <- err
	}()
	go func() { wg.Wait(); close(results) }()
	var firstErr error
	for out := range results {
		if out.event.Action != "" {
			switch out.event.Action {
			case ActionImported:
				result.Imported++
				result.Bytes += out.event.Bytes
			case ActionPlanned:
				result.Planned++
				result.Bytes += out.event.Bytes
			case ActionSkipped:
				result.Skipped++
			case ActionUnsupported:
				result.Unsupported++
			case ActionFailed:
				result.Failed++
			}
			emitter.emit(out.event)
		}
		if out.stop && firstErr == nil {
			firstErr = out.event.Err
		}
	}
	walkErr := <-walkDone
	if firstErr == nil {
		firstErr = walkErr
	}
	if firstErr == nil && ctx.Err() != nil {
		firstErr = ctx.Err()
	}
	return result, firstErr
}

func process(ctx context.Context, root *importRoot, backend rsserver.StorageBackend, j job, opts Options) outcome {
	fail := func(err error) outcome {
		return outcome{event: Event{Path: j.path, Action: ActionFailed, Err: err}, stop: true}
	}
	if !opts.AllowPublic && strings.HasPrefix(j.path, "/public/") {
		return fail(errors.New("public destination requires AllowPublic"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	stBefore, err := root.statFile(j.rel)
	if err != nil {
		return fail(err)
	}
	size := stBefore.Size()
	if size < 0 {
		return fail(errors.New("invalid source file size"))
	}
	pctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	meta, err := backend.Head(pctx, j.path)
	exists := err == nil && meta != nil && !meta.IsFolder
	if err != nil && !errors.Is(err, rs.ErrNotFound) {
		return fail(err)
	}
	if meta != nil && meta.IsFolder {
		return fail(rs.ErrConflict)
	}
	if exists {
		switch opts.Existing {
		case ExistingSkip:
			return outcome{event: Event{Path: j.path, Action: ActionSkipped}}
		case ExistingError:
			return fail(fmt.Errorf("destination already exists: %s", j.path))
		}
	}
	if opts.MaxDocumentBytes > 0 && size > opts.MaxDocumentBytes {
		return fail(rs.ErrTooLarge)
	}
	if opts.DryRun {
		return outcome{event: Event{Path: j.path, Action: ActionPlanned, Bytes: size}}
	}
	cond := rsserver.Condition{IfNoneMatchAny: !exists}
	if exists {
		cond.IfMatch = []string{meta.ETag}
	}
	source, st, err := root.openFile(j.rel)
	if err != nil {
		return fail(err)
	}
	defer source.Close()
	n := st.Size()
	if n != size || !sameSourceVersion(stBefore, st) {
		return fail(errors.New("source changed while importing"))
	}
	if n < 0 || (opts.MaxDocumentBytes > 0 && n > opts.MaxDocumentBytes) {
		return fail(rs.ErrTooLarge)
	}
	mimeType := mime.TypeByExtension(filepath.Ext(j.rel))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	reader := &checkedReader{ctx: pctx, f: source, size: n, initial: st}
	var sniff [512]byte
	k, readErr := io.ReadFull(reader, sniff[:])
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return fail(readErr)
	}
	if mimeType == "application/octet-stream" && k > 0 {
		mimeType = http.DetectContentType(sniff[:k])
	}
	body := io.MultiReader(strings.NewReader(string(sniff[:k])), reader)
	_, err = backend.Put(pctx, j.path, body, n, mimeType, cond)
	if err != nil {
		return fail(err)
	}
	return outcome{event: Event{Path: j.path, Action: ActionImported, Bytes: n}}
}

type checkedReader struct {
	ctx     context.Context
	f       *os.File
	size, n int64
	initial os.FileInfo
}

func (r *checkedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.n > r.size {
		return 0, errors.New("source grew")
	}
	if r.n == r.size {
		var one [1]byte
		n, err := r.f.Read(one[:])
		if n > 0 {
			r.n += int64(n)
			return 0, errors.New("source grew")
		}
		if err == io.EOF {
			if stat, statErr := r.f.Stat(); statErr != nil {
				return 0, statErr
			} else if !sameSourceVersion(r.initial, stat) || stat.Size() != r.size {
				return 0, errors.New("source changed while importing")
			}
		}
		return 0, err
	}
	if int64(len(p)) > r.size-r.n {
		p = p[:r.size-r.n]
	}
	n, err := r.f.Read(p)
	r.n += int64(n)
	if err == io.EOF && r.n != r.size {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}
func validateFolderPath(p string) error {
	if !utf8.ValidString(p) || len(p) > maxPathBytes || !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/") || strings.Contains(p, "\\") || path.Clean(p)+"/" != p && p != "/" || strings.Count(p, "/") > maxPathSlashes || rs.ValidatePath(p) != nil {
		return rs.ErrInvalidPath
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return rs.ErrInvalidPath
		}
	}
	return nil
}
func validateRemote(p string) error {
	if !utf8.ValidString(p) || len(p) > maxPathBytes || strings.Count(p, "/") > maxPathSlashes || strings.Contains(p, "\\") || path.Clean(p) != p || rs.ValidatePath(p) != nil || rs.IsFolderPath(p) {
		return rs.ErrInvalidPath
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return rs.ErrInvalidPath
		}
	}
	return nil
}
