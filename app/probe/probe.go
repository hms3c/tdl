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
	URLs   []string
	Files  []string
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
	DialogID int64  `json:"dialog_id"`
	MessageID int   `json:"message_id"`
	FileName string `json:"file_name"`
	FileSize int64  `json:"file_size"`
	DC       int    `json:"dc"`

	PartStart   int64 `json:"part_start"`
	PartLength  int64 `json:"part_length"`
	Downloaded  int64 `json:"downloaded"`

	HashAlgo string `json:"hash_algo"`
	Hash     string `json:"hash"`

	MessageDate int64  `json:"message_date,omitempty"`
	Caption     string `json:"caption,omitempty"`
}

func Run(ctx context.Context, c *telegram.Client, kvd storage.Storage, opts Options) (rerr error) {
	if opts.LimitMB <= 0 {
		return errors.New("limit-mb must be greater than 0")
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
	if want <= 0 {
		return errors.New("computed part length is zero")
	}

	client := pool.Client(ctx, media.DC)
	if opts.Takeout {
		client = pool.Takeout(ctx, media.DC)
	}

	hashHex, downloaded, err := hashPartial(ctx, client, media.InputFileLoc, start, want, opts.Algo)
	if err != nil {
		return err
	}

	res := Result{
		DialogID:    from.ID(),
		MessageID:   msg.ID,
		FileName:    media.Name,
		FileSize:    media.Size,
		DC:          media.DC,
		PartStart:   start,
		PartLength:  want,
		Downloaded:  downloaded,
		HashAlgo:    strings.ToLower(opts.Algo),
		Hash:        hashHex,
		MessageDate: int64(msg.Date),
		Caption:     msg.Message,
	}
	enc := json.NewEncoder(stdoutWriter{})
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res); err != nil {
		return errors.Wrap(err, "encode result")
	}
	return nil
}

func computeRange(size int64, opts Options) (start int64, length int64) {
	want := int64(opts.LimitMB) * 1024 * 1024
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

// stdoutWriter implements io.Writer to write to STDOUT using fmt.Print (avoids import of os in this file).
type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) {
	// Avoid interleaving with logs: add timestamped prefix for safety if needed.
	// Here we just print directly.
	fmt.Print(string(p))
	return len(p), nil
}

func hashPartial(ctx context.Context, api *tg.Client, loc tg.InputFileLocationClass, start, length int64, algo string) (string, int64, error) {
	var downloaded int64

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
			return "", downloaded, ctx.Err()
		default:
		}

		want := end - offset
		if want > maxPart {
			want = maxPart
		}

		res, err := api.UploadGetFile(ctx, &tg.UploadGetFileRequest{
			Precise:      true,
			CDNSupported: false,
			Location:     loc,
			Offset:       offset,
			Limit:        int(want),
		})
		if err != nil {
			return "", downloaded, errors.Wrap(err, "UploadGetFile")
		}

		switch f := res.(type) {
		case *tg.UploadFile:
			// f.Bytes contains file data payload for this chunk.
			if len(f.Bytes) == 0 {
				// No more data
				offset = end
				break
			}
			if _, err := hasher.Write(f.Bytes); err != nil {
				return "", downloaded, errors.Wrap(err, "hash write")
			}
			n := int64(len(f.Bytes))
			downloaded += n
			offset += n
		default:
			return "", downloaded, errors.Errorf("unexpected UploadGetFileResult: %T", f)
		}
	}

	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), downloaded, nil
}


