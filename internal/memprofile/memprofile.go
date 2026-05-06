package memprofile

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"time"
)

type snapshot struct {
	Label     string
	Time      time.Time
	HeapAlloc uint64
	HeapInUse uint64
	HeapSys   uint64
	TotalAlloc uint64
	NumGC     uint32
	Mallocs   uint64
	Frees     uint64
	StackInUse uint64
	GoRoutines int
}

var (
	mu        sync.Mutex
	snapshots []snapshot
	enabled   bool
	startTime time.Time
	profileDir string
)

func init() {
	enabled = os.Getenv("EC_MEMPROFILE") != ""
	profileDir = os.Getenv("EC_MEMPROFILE_DIR")
}

func Enabled() bool {
	return enabled
}

// Snapshot captures a memory stats snapshot with the given label.
// No-op if EC_MEMPROFILE is not set.
func Snapshot(label string) {
	if !enabled {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if len(snapshots) == 0 {
		startTime = time.Now()
	}

	runtime.GC()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	snapshots = append(snapshots, snapshot{
		Label:      label,
		Time:       time.Now(),
		HeapAlloc:  m.HeapAlloc,
		HeapInUse:  m.HeapInuse,
		HeapSys:    m.HeapSys,
		TotalAlloc: m.TotalAlloc,
		NumGC:      m.NumGC,
		Mallocs:    m.Mallocs,
		Frees:      m.Frees,
		StackInUse: m.StackInuse,
		GoRoutines: runtime.NumGoroutine(),
	})

	if profileDir != "" {
		writeHeapProfile(label, len(snapshots))
	}
}

func writeHeapProfile(label string, idx int) {
	safe := strings.NewReplacer(" ", "_", "/", "_", ":", "_").Replace(label)
	path := fmt.Sprintf("%s/heap_%02d_%s.pprof", profileDir, idx, safe)
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[memprofile] failed to create %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Fprintf(os.Stderr, "[memprofile] failed to write heap profile: %v\n", err)
	}
}

func mb(b uint64) float64 {
	return float64(b) / 1024 / 1024
}

// Report prints a summary table of all captured snapshots to stderr.
// No-op if no snapshots were taken.
func Report() {
	mu.Lock()
	defer mu.Unlock()

	if len(snapshots) == 0 {
		return
	}

	fmt.Fprintln(os.Stderr, "\n══════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(os.Stderr, "  EC Memory Profile Report")
	fmt.Fprintln(os.Stderr, "══════════════════════════════════════════════════════════════════════")
	fmt.Fprintf(os.Stderr, "%-4s  %-40s  %8s  %10s  %10s  %10s  %10s  %6s  %5s\n",
		"#", "Phase", "Elapsed", "HeapAlloc", "HeapInUse", "TotalAlloc", "StackInUse", "GCs", "GoRtn")
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 120))

	for i, s := range snapshots {
		elapsed := s.Time.Sub(startTime)
		fmt.Fprintf(os.Stderr, "%-4d  %-40s  %7.1fs  %8.1f MB  %8.1f MB  %8.1f MB  %8.1f MB  %6d  %5d\n",
			i+1, truncate(s.Label, 40), elapsed.Seconds(),
			mb(s.HeapAlloc), mb(s.HeapInUse), mb(s.TotalAlloc), mb(s.StackInUse),
			s.NumGC, s.GoRoutines)
	}

	fmt.Fprintln(os.Stderr, strings.Repeat("─", 120))

	// Print phase deltas (biggest memory consumers)
	type delta struct {
		Label     string
		HeapDelta int64
		AllocDelta uint64
		Duration  time.Duration
	}
	var deltas []delta
	for i := 1; i < len(snapshots); i++ {
		d := delta{
			Label:      snapshots[i].Label,
			HeapDelta:  int64(snapshots[i].HeapInUse) - int64(snapshots[i-1].HeapInUse),
			AllocDelta: snapshots[i].TotalAlloc - snapshots[i-1].TotalAlloc,
			Duration:   snapshots[i].Time.Sub(snapshots[i-1].Time),
		}
		deltas = append(deltas, d)
	}

	// Sort by allocation delta descending
	sort.Slice(deltas, func(i, j int) bool {
		return deltas[i].AllocDelta > deltas[j].AllocDelta
	})

	fmt.Fprintln(os.Stderr, "\n  Top memory-consuming phases (by total allocations):")
	fmt.Fprintf(os.Stderr, "  %-40s  %12s  %12s  %10s\n", "Phase", "HeapΔ", "Allocated", "Duration")
	fmt.Fprintln(os.Stderr, "  "+strings.Repeat("─", 80))

	for i, d := range deltas {
		if i >= 10 {
			break
		}
		heapSign := "+"
		heapAbs := d.HeapDelta
		if heapAbs < 0 {
			heapSign = "-"
			heapAbs = -heapAbs
		}
		fmt.Fprintf(os.Stderr, "  %-40s  %s%8.1f MB  %8.1f MB  %9.1fs\n",
			truncate(d.Label, 40), heapSign, mb(uint64(heapAbs)), mb(d.AllocDelta), d.Duration.Seconds())
	}

	if profileDir != "" {
		fmt.Fprintf(os.Stderr, "\n  Heap profiles written to: %s/\n", profileDir)
		fmt.Fprintln(os.Stderr, "  Analyze with: go tool pprof -http=:8080 <file>.pprof")
		fmt.Fprintln(os.Stderr, "  Compare phases: go tool pprof -diff_base=heap_01_*.pprof heap_05_*.pprof")
	}

	fmt.Fprintln(os.Stderr, "══════════════════════════════════════════════════════════════════════")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
