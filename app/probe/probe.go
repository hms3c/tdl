package probe

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-faster/errors"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/peers"
	"github.com/gotd/td/tg"
	"github.com/iyear/tdl/pkg/filemagic"
	"github.com/spf13/viper"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/iyear/tdl/core/dcpool"
	"github.com/iyear/tdl/core/logctx"
	"github.com/iyear/tdl/core/storage"
	"github.com/iyear/tdl/core/tclient"
	"github.com/iyear/tdl/core/tmedia"
	"github.com/iyear/tdl/core/util/tutil"
	"github.com/iyear/tdl/pkg/consts"
	"github.com/iyear/tdl/pkg/tmessage"
)

// Options defines input and hashing parameters for partial download hashing.
type Options struct {
	URLs    []string
	Files   []string
	Takeout bool

	// LimitMB is how many MB to download for hashing (required > 0).
	LimitMB int
	// OffsetBytes is the start position in bytes from the beginning when Tail is false.
	OffsetBytes int64
	// Tail indicates to take the last LimitMB from the end of file (OffsetBytes ignored).
	Tail bool
	// Algo is the hashing algorithm, supports: sha256 (default), sha1, md5
	Algo string
}

type parser struct {
	Data   []string
	Parser tmessage.ParseSource
}

// Result is the JSON result printed for each processed media.
type Result struct {
	ChannelId int64  `json:"ChannelId"`
	MessageID int    `json:"MessageID"`
	FileName  string `json:"FileName"`
	FileSize  int64  `json:"FileSize"`
	DC        int    `json:"DC"`

	PartStart  int64 `json:"PartStart"`
	PartLength int64 `json:"PartLength"`
	Downloaded int64 `json:"Downloaded"`

	FileHash     string `json:"FileHash"`
	FileHashAlgo string `json:"FileHashAlgo"`

	FileHeader *HeaderSummary `json:"FileHeader,omitempty"`

	MessageDate int64  `json:"MessageDate,omitempty"`
	Caption     string `json:"Caption,omitempty"`
	Error       string `json:"Error,omitempty"`

	// MessageDocument is the raw tg.MessageDocument from Telegram message media (if available).
	MessageDocument *tg.Document `json:"MessageDocument,omitempty"`
}

// HeaderSummary contains the first chunk (header) and its hash.
type HeaderSummary struct {
	Hash        string   `json:"Hash"` // sha256 of header bytes
	Type        string   `json:"Type,omitempty"`
	Description string   `json:"Description,omitempty"`
	Extensions  []string `json:"Extensions,omitempty"`
}

func Run(ctx context.Context, c *telegram.Client, kvd storage.Storage, opts Options) (rerr error) {
	if opts.LimitMB <= 0 {
		return errors.New("limit must be greater than 0")
	}
	if opts.Algo == "" {
		opts.Algo = "sha256"
	}

	pool := dcpool.NewPool(c,
		int64(viper.GetInt(consts.FlagPoolSize)),
		tclient.NewDefaultMiddlewares(ctx, viper.GetDuration(consts.FlagReconnectTimeout))...)
	defer multierr.AppendInvoke(&rerr, multierr.Close(pool))

	parsers := []parser{
		{Data: opts.URLs, Parser: tmessage.FromURL(ctx, pool, kvd, opts.URLs)},
		{Data: opts.Files, Parser: tmessage.FromFile(ctx, pool, kvd, opts.Files, true)},
	}
	dialogs, err := collectDialogs(parsers)
	if err != nil {
		return err
	}
	logctx.From(ctx).Debug("Collect dialogs",
		zap.Any("dialogs", dialogs))

	manager := peers.Options{Storage: storage.NewPeers(kvd)}.Build(pool.Default(ctx))

	for _, group := range dialogs {
		for _, d := range group {
			for _, msgID := range d.Messages {
				if err := handleOne(ctx, pool, manager, d.Peer, msgID, opts); err != nil {
					// print error in-line and continue to next
					logctx.From(ctx).Warn("probe error",
						zap.Any("peer", d.Peer),
						zap.Int("message", msgID),
						zap.Error(err))
				}
			}
		}
	}
	return nil
}

func collectDialogs(parsers []parser) ([][]*tmessage.Dialog, error) {
	var dialogs [][]*tmessage.Dialog
	for _, p := range parsers {
		d, err := tmessage.Parse(p.Parser)
		if err != nil {
			return nil, err
		}
		dialogs = append(dialogs, d)
	}
	return dialogs, nil
}

func handleOne(ctx context.Context, pool dcpool.Pool, manager *peers.Manager, peer tg.InputPeerClass, msgID int, opts Options) error {
	from, err := manager.FromInputPeer(ctx, peer)
	if err != nil {
		return errors.Wrap(err, "resolve from input peer")
	}
	msg, err := tutil.GetSingleMessage(ctx, pool.Default(ctx), peer, msgID)
	if err != nil {
		return errors.Wrap(err, "resolve message")
	}
	media, ok := tmedia.GetMedia(msg)
	if !ok {
		// skip silently
		return nil
	}

	start, want := computeRange(media.Size, opts)

	// fmt.Printf("[handleOne] media.size: %v, start: %v + want: %v = %v\n ", media.Size, start, want, start+want)

	client := pool.Client(ctx, media.DC)
	if opts.Takeout {
		client = pool.Takeout(ctx, media.DC)
	}

	res := Result{
		ChannelId:    from.ID(),
		MessageID:    msg.ID,
		FileName:     media.Name,
		FileSize:     media.Size,
		DC:           media.DC,
		PartStart:    start,
		PartLength:   want,
		FileHashAlgo: strings.ToLower(opts.Algo),
		MessageDate:  int64(msg.Date),
		Caption:      msg.Message,
	}
	// Populate raw tg.Document when present in message media
	if mm, ok := msg.GetMedia(); ok {
		if md, ok := mm.(*tg.MessageMediaDocument); ok {
			if d, dok := md.Document.(*tg.Document); dok {
				res.MessageDocument = d
			}
		}
	}
	enc := json.NewEncoder(stdoutWriter{})
	enc.SetEscapeHTML(false)

	// If range is empty, emit a record with error info and continue.
	if want <= 0 {
		res.Error = "computed part length is zero"
		if err := enc.Encode(res); err != nil {
			return errors.Wrap(err, "encode result (empty range)")
		}
		return nil
	}

	hashHex, downloaded, headerBytes, headerHash, err := hashPartialSmart(ctx, client, media.InputFileLoc, start, want, opts.Algo)
	if err != nil {
		// Fallback to aligned mode if precise request failed (some servers may not support Precise).
		if fh, fd, fhb, fhh, ferr := hashPartialAligned(ctx, client, media.InputFileLoc, start, want, opts.Algo); ferr == nil {
			hashHex, downloaded, headerBytes, headerHash = fh, fd, fhb, fhh
			err = nil
		}
	}
	if err != nil {
		res.Downloaded = downloaded
		res.Error = err.Error()
		if err := enc.Encode(res); err != nil {
			return errors.Wrap(err, "encode result (error)")
		}
		return nil
	}

	// Only when processing from file start, include header if available.
	if start == 0 && len(headerBytes) > 0 {
		h := &HeaderSummary{
			Hash: headerHash,
		}
		if m, ok := filemagic.Identify(headerBytes); ok {
			h.Type = m.Type
			h.Description = m.Description
			h.Extensions = m.Extensions
		}
		res.FileHeader = h
	}

	res.Downloaded = downloaded
	res.FileHash = hashHex
	if err := enc.Encode(res); err != nil {
		return errors.Wrap(err, "encode result")
	}
	return nil
}

func computeRange(size int64, opts Options) (start int64, length int64) {
	want := int64(opts.LimitMB) * 1024 * 1024
	if want <= 0 {
		fmt.Printf("[computeRange] want is less than or equal to 0\n")
		return 0, 0
	}
	if opts.Tail {
		if want >= size {
			return 0, size
		}
		return size - want, want
	}
	if opts.OffsetBytes < 0 {
		opts.OffsetBytes = 0
	}
	if opts.OffsetBytes >= size {
		return size, 0
	}
	remaining := size - opts.OffsetBytes
	if want >= remaining {
		return opts.OffsetBytes, remaining
	}
	return opts.OffsetBytes, want
}

// hashPartialSmart chooses the best strategy depending on offset alignment.
func hashPartialSmart(ctx context.Context, api *tg.Client, loc tg.InputFileLocationClass, start, length int64, algo string) (string, int64, []byte, string, error) {
	const miB = int64(1024 * 1024)
	if start%miB != 0 {
		return hashPartialMiBAligned(ctx, api, loc, start, length, algo)
	}
	return hashPartial(ctx, api, loc, start, length, algo)
}

// stdoutWriter implements io.Writer to write to STDOUT using fmt.Print (avoids import of os in this file).
type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) {
	// Avoid interleaving with logs: add timestamped prefix for safety if needed.
	// Here we just print directly.
	fmt.Print(string(p))
	return len(p), nil
}

func hashPartial(ctx context.Context, api *tg.Client, loc tg.InputFileLocationClass, start, length int64, algo string) (string, int64, []byte, string, error) {
	var downloaded int64
	var headerBytes []byte
	var headerHash string

	var hasher interface {
		Write(p []byte) (int, error)
		Sum(b []byte) []byte
	}
	switch strings.ToLower(algo) {
	case "sha1":
		hasher = sha1.New()
	case "md5":
		hasher = md5.New()
	default:
		hasher = sha256.New()
	}

	const maxPart = 1024 * 1024 // 1 MiB, consistent with downloader.MaxPartSize
	offset := start
	end := start + length

	// UploadGetFile may require part sizes aligned; we set Precise=true for last chunk.
	for offset < end {
		select {
		case <-ctx.Done():
			return "", downloaded, nil, "", ctx.Err()
		default:
		}

		// want := end - offset
		// if want > maxPart {
		// 	want = maxPart
		// }

		want := int64(maxPart)

		// fmt.Printf("[hashPartial] before -> length: %v, offset: %v, end: %v, want: %v\n", length, offset, end, want)

		res, err := api.UploadGetFile(ctx, &tg.UploadGetFileRequest{
			Precise:      false,
			CDNSupported: false,
			Location:     loc,
			Offset:       offset,
			Limit:        int(want),
		})
		if err != nil {
			return "", downloaded, nil, "", errors.Wrap(err, "UploadGetFile")
		}

		switch f := res.(type) {
		case *tg.UploadFile:
			// f.Bytes contains file data payload for this chunk.
			if len(f.Bytes) == 0 {
				// No more data
				offset = end
				break
			}
			// Capture header bytes on the first chunk if reading from start of file
			if start == 0 && headerBytes == nil {
				n := len(f.Bytes)
				if n > 1024 {
					n = 1024
				}
				headerBytes = append([]byte(nil), f.Bytes[:n]...)
				sum := sha256.Sum256(headerBytes)
				headerHash = hex.EncodeToString(sum[:])
			}
			if _, err := hasher.Write(f.Bytes); err != nil {
				return "", downloaded, headerBytes, headerHash, errors.Wrap(err, "hash write")
			}
			n := int64(len(f.Bytes))
			downloaded += n
			offset += n
		default:
			return "", downloaded, headerBytes, headerHash, errors.Errorf("unexpected UploadGetFileResult: %T", f)
		}
	}

	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), downloaded, headerBytes, headerHash, nil
}

// hashPartialMiBAligned aligns starting offset to 1MiB for non-precise mode and trims prefix.
func hashPartialMiBAligned(ctx context.Context, api *tg.Client, loc tg.InputFileLocationClass, start, length int64, algo string) (string, int64, []byte, string, error) {
	var downloaded int64
	var headerBytes []byte
	var headerHash string

	var hasher interface {
		Write(p []byte) (int, error)
		Sum(b []byte) []byte
	}
	switch strings.ToLower(algo) {
	case "sha1":
		hasher = sha1.New()
	case "md5":
		hasher = md5.New()
	default:
		hasher = sha256.New()
	}

	const maxPart = 1024 * 1024
	const align = int64(1024 * 1024)

	alignedStart := start - (start % align)
	skipPrefix := start - alignedStart

	offset := alignedStart
	end := start + length

	for offset < end {
		select {
		case <-ctx.Done():
			return "", downloaded, nil, "", ctx.Err()
		default:
		}

		want := int64(maxPart)
		// want := end - offset
		// if want > maxPart {
		// 	want = maxPart
		// }

		// fmt.Printf("[hashPartialMiBAligned] before -> length: %v, offset: %v + want: %v = %v, end: %v\n", length, offset, want, offset+want, end)

		res, err := api.UploadGetFile(ctx, &tg.UploadGetFileRequest{
			Precise:      false,
			CDNSupported: false,
			Location:     loc,
			Offset:       offset,
			Limit:        int(want),
		})
		if err != nil {
			return "", downloaded, nil, "", errors.Wrap(err, "UploadGetFile (1MiB aligned)")
		}

		switch f := res.(type) {
		case *tg.UploadFile:
			data := f.Bytes
			if len(data) == 0 {
				offset = end
				break
			}
			var begin int64 = 0
			if offset == alignedStart && skipPrefix > 0 {
				begin = skipPrefix
				if begin > int64(len(data)) {
					begin = int64(len(data))
				}
			}
			// Capture header only when overall start == 0 (alignedStart should be 0 too)
			if start == 0 && headerBytes == nil && begin == 0 {
				n := len(data)
				if n > 1024 {
					n = 1024
				}
				headerBytes = append([]byte(nil), data[:n]...)
				sum := sha256.Sum256(headerBytes)
				headerHash = hex.EncodeToString(sum[:])
			}
			remaining := end - offset
			maxWrite := int64(len(data)) - begin
			if remaining < maxWrite {
				maxWrite = remaining
			}
			if maxWrite > 0 {
				chunk := data[begin : begin+maxWrite]
				if _, err := hasher.Write(chunk); err != nil {
					return "", downloaded, headerBytes, headerHash, errors.Wrap(err, "hash write (1MiB aligned)")
				}
				downloaded += int64(len(chunk))
			}
			offset += int64(len(data))
		default:
			return "", downloaded, headerBytes, headerHash, errors.Errorf("unexpected UploadGetFileResult: %T", f)
		}
	}

	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), downloaded, headerBytes, headerHash, nil
}

// hashPartialAligned retries hashing when server requires 4KiB aligned offsets.
// It starts reading from floor(start, 4096) with Precise=false and only hashes bytes within [start, start+length).
func hashPartialAligned(ctx context.Context, api *tg.Client, loc tg.InputFileLocationClass, start, length int64, algo string) (string, int64, []byte, string, error) {
	var downloaded int64
	var headerBytes []byte
	var headerHash string

	var hasher interface {
		Write(p []byte) (int, error)
		Sum(b []byte) []byte
	}
	switch strings.ToLower(algo) {
	case "sha1":
		hasher = sha1.New()
	case "md5":
		hasher = md5.New()
	default:
		hasher = sha256.New()
	}

	const maxPart = 1024 * 1024
	const align = 4096

	alignedStart := start - (start % align)
	skipPrefix := start - alignedStart

	offset := alignedStart
	end := start + length

	for offset < end {
		select {
		case <-ctx.Done():
			return "", downloaded, nil, "", ctx.Err()
		default:
		}

		want := end - offset
		if want > maxPart {
			want = maxPart // todo: verificar se dara problema, se sim mudar o predize para false e colocar want = maxPart msm
		}

		res, err := api.UploadGetFile(ctx, &tg.UploadGetFileRequest{
			Precise:      true,
			CDNSupported: false,
			Location:     loc,
			Offset:       offset,
			Limit:        int(want),
		})
		if err != nil {
			return "", downloaded, nil, "", errors.Wrap(err, "UploadGetFile (aligned)")
		}

		switch f := res.(type) {
		case *tg.UploadFile:
			data := f.Bytes
			if len(data) == 0 {
				offset = end
				break
			}
			var begin int64 = 0
			if offset == alignedStart && skipPrefix > 0 {
				begin = skipPrefix
				if begin > int64(len(data)) {
					begin = int64(len(data))
				}
			}
			// Capture header only when overall start == 0 (alignedStart should be 0 too)
			if start == 0 && headerBytes == nil && begin == 0 {
				n := len(data)
				if n > 1024 {
					n = 1024
				}
				headerBytes = append([]byte(nil), data[:n]...)
				sum := sha256.Sum256(headerBytes)
				headerHash = hex.EncodeToString(sum[:])
			}
			remaining := end - offset
			maxWrite := int64(len(data)) - begin
			if remaining < maxWrite {
				maxWrite = remaining
			}
			if maxWrite > 0 {
				chunk := data[begin : begin+maxWrite]
				if _, err := hasher.Write(chunk); err != nil {
					return "", downloaded, headerBytes, headerHash, errors.Wrap(err, "hash write (aligned)")
				}
				downloaded += int64(len(chunk))
			}
			offset += int64(len(data))
		default:
			return "", downloaded, headerBytes, headerHash, errors.Errorf("unexpected UploadGetFileResult: %T", f)
		}
	}

	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), downloaded, headerBytes, headerHash, nil
}
