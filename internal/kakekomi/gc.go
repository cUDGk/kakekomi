package kakekomi

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"
)

// Gc runs a one-shot TTL sweep (for cron / manual cleanup).
func Gc(args []string) error {
	fs := flag.NewFlagSet("gc", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := OpenStore(*dataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	n, err := store.GC()
	if err != nil {
		return err
	}
	fmt.Printf("✓ removed %d expired case(s)\n", n)
	return nil
}

// runGCLoop periodically sweeps expired cases until ctx is cancelled.
func runGCLoop(ctx context.Context, store *Store, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := store.GC(); err != nil {
				log.Printf("gc: %v", err)
			} else if n > 0 {
				log.Printf("gc: removed %d expired case(s)", n)
			}
		}
	}
}
