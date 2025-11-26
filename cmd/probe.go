package cmd

import (
	"context"
	"fmt"

	"github.com/gotd/td/telegram"
	"github.com/spf13/cobra"

	"github.com/iyear/tdl/app/probe"
	"github.com/iyear/tdl/core/logctx"
	"github.com/iyear/tdl/core/storage"
)

func NewProbe() *cobra.Command {
	var opts probe.Options

	cmd := &cobra.Command{
		Use:     "probe",
		Aliases: []string{"inspect", "hash"},
		Short:   "Download a small part of media to hash and return details",
		GroupID: groupTools.ID,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(opts.URLs) == 0 && len(opts.Files) == 0 {
				return fmt.Errorf("no urls or files provided")
			}
			if opts.LimitMB <= 0 {
				return fmt.Errorf("limit-mb must be greater than 0")
			}

			return tRun(cmd.Context(), func(ctx context.Context, c *telegram.Client, kvd storage.Storage) error {
				return probe.Run(logctx.Named(ctx, "probe"), c, kvd, opts)
			})
		},
	}

	const (
		file = "file"
	)

	cmd.Flags().StringSliceVarP(&opts.URLs, "url", "u", []string{}, "telegram message links")
	cmd.Flags().StringSliceVarP(&opts.Files, file, "f", []string{}, "official client exported files")
	cmd.Flags().BoolVar(&opts.Takeout, "takeout", false, "use takeout session for lower flood wait limits")

	cmd.Flags().IntVar(&opts.LimitMB, "limit-mb", 10, "number of megabytes to download for hashing")
	cmd.Flags().Int64Var(&opts.OffsetBytes, "offset", 0, "start offset in bytes (ignored when --tail is set)")
	cmd.Flags().BoolVar(&opts.Tail, "tail", false, "hash the last --limit-mb megabytes of the file")
	cmd.Flags().StringVar(&opts.Algo, "algo", "sha256", "hash algorithm: sha256 (default), sha1, md5")

	_ = cmd.RegisterFlagCompletionFunc(file, completeExtFiles("json"))

	return cmd
}


