// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package profile provides runtime profiling for acceptance tests.
// Tracks per-scenario timing, container startup stats, and Kind cluster phases.
// Results are printed to stderr and written to /tmp/ec-profile/.
package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var enabled = true

type ctxKey int

const scenarioStartKey ctxKey = 0

type phaseTiming struct {
	Name     string
	Duration time.Duration
}

type containerStats struct {
	Count int
	Total time.Duration
	Min   time.Duration
	Max   time.Duration
}

type scenarioTiming struct {
	Name     string
	Feature  string
	Duration time.Duration
}

var (
	mu         sync.Mutex
	fileMu     sync.Mutex
	suiteStart time.Time
	outputFile *os.File
	outputDir  string
	reported   sync.Once

	phases         []phaseTiming
	containerTypes map[string]*containerStats
	scenarioList   []scenarioTiming

	activeContainers atomic.Int64
	peakContainers   int64
)

// Init initializes profiling. Call once at suite start.
func Init() {
	if !enabled {
		return
	}
	suiteStart = time.Now()
	containerTypes = make(map[string]*containerStats)

	outputDir = "/tmp/ec-profile"
	if d := os.Getenv("EC_PROFILE_DIR"); d != "" {
		outputDir = d
	}
	os.MkdirAll(outputDir, 0755)
	f, err := os.Create(filepath.Join(outputDir, "events.jsonl"))
	if err == nil {
		outputFile = f
	}
}

func logEvent(data map[string]any) {
	if outputFile == nil {
		return
	}
	b, _ := json.Marshal(data)
	fileMu.Lock()
	outputFile.Write(append(b, '\n'))
	outputFile.Sync()
	fileMu.Unlock()
}

// Begin starts timing a named phase. Call the returned function to stop and record.
func Begin(name string) func() {
	if !enabled {
		return func() {}
	}
	start := time.Now()
	return func() {
		dur := time.Since(start)
		mu.Lock()
		phases = append(phases, phaseTiming{Name: name, Duration: dur})
		mu.Unlock()
		logEvent(map[string]any{
			"event": "phase", "name": name,
			"duration_ms": dur.Milliseconds(), "ts": time.Now().Format(time.RFC3339),
		})
	}
}

// BeginContainer starts timing a container creation. Call the returned function when ready.
func BeginContainer(containerType string) func() {
	if !enabled {
		return func() {}
	}
	start := time.Now()
	return func() {
		dur := time.Since(start)
		mu.Lock()
		stats, ok := containerTypes[containerType]
		if !ok {
			stats = &containerStats{Min: dur}
			containerTypes[containerType] = stats
		}
		stats.Count++
		stats.Total += dur
		if dur < stats.Min {
			stats.Min = dur
		}
		if dur > stats.Max {
			stats.Max = dur
		}
		mu.Unlock()

		current := activeContainers.Add(1)
		mu.Lock()
		if current > peakContainers {
			peakContainers = current
		}
		mu.Unlock()

		logEvent(map[string]any{
			"event": "container", "type": containerType,
			"duration_ms": dur.Milliseconds(), "ts": time.Now().Format(time.RFC3339),
		})
	}
}

// ScenarioStart marks the beginning of a scenario. Returns updated context.
func ScenarioStart(ctx context.Context) context.Context {
	if !enabled {
		return ctx
	}
	return context.WithValue(ctx, scenarioStartKey, time.Now())
}

// ScenarioEnd records the scenario duration.
func ScenarioEnd(ctx context.Context, name, feature string) {
	if !enabled {
		return
	}
	start, ok := ctx.Value(scenarioStartKey).(time.Time)
	if !ok {
		return
	}
	dur := time.Since(start)
	mu.Lock()
	scenarioList = append(scenarioList, scenarioTiming{Name: name, Feature: feature, Duration: dur})
	mu.Unlock()

	logEvent(map[string]any{
		"event": "scenario", "name": name, "feature": feature,
		"duration_ms": dur.Milliseconds(), "ts": time.Now().Format(time.RFC3339),
	})
}

// Report prints the profiling summary. Safe to call multiple times (runs once).
func Report() {
	if !enabled {
		return
	}
	reported.Do(doReport)
}

func doReport() {
	totalDur := time.Since(suiteStart)

	var buf bytes.Buffer
	w := &buf

	fmt.Fprintf(w, "\n==========================================\n")
	fmt.Fprintf(w, "  ACCEPTANCE TEST PROFILING REPORT\n")
	fmt.Fprintf(w, "==========================================\n")
	fmt.Fprintf(w, "Total wall-clock time: %s\n", totalDur.Round(time.Millisecond))
	fmt.Fprintf(w, "Goroutine concurrency: %d (runtime.NumCPU)\n\n", runtime.NumCPU())

	mu.Lock()
	pCopy := make([]phaseTiming, len(phases))
	copy(pCopy, phases)
	mu.Unlock()

	if len(pCopy) > 0 {
		fmt.Fprintf(w, "--- One-off Phases ---\n")
		for _, ph := range pCopy {
			pct := float64(ph.Duration) / float64(totalDur) * 100
			fmt.Fprintf(w, "  %-40s %10s  (%5.1f%%)\n",
				ph.Name, ph.Duration.Round(time.Millisecond), pct)
		}
		fmt.Fprintln(w)
	}

	mu.Lock()
	types := make([]string, 0, len(containerTypes))
	for t := range containerTypes {
		types = append(types, t)
	}
	cCopy := make(map[string]containerStats)
	for t, s := range containerTypes {
		cCopy[t] = *s
	}
	peak := peakContainers
	active := activeContainers.Load()
	mu.Unlock()
	sort.Strings(types)

	if len(types) > 0 {
		fmt.Fprintf(w, "--- Container Startup Statistics ---\n")
		fmt.Fprintf(w, "  %-12s %5s %10s %10s %10s %10s\n", "TYPE", "COUNT", "TOTAL", "AVG", "MIN", "MAX")
		totalCount := 0
		totalDurC := time.Duration(0)
		for _, t := range types {
			s := cCopy[t]
			avg := s.Total / time.Duration(s.Count)
			fmt.Fprintf(w, "  %-12s %5d %10s %10s %10s %10s\n",
				t, s.Count,
				s.Total.Round(time.Millisecond), avg.Round(time.Millisecond),
				s.Min.Round(time.Millisecond), s.Max.Round(time.Millisecond))
			totalCount += s.Count
			totalDurC += s.Total
		}
		fmt.Fprintf(w, "  %-12s %5d %10s\n", "TOTAL", totalCount, totalDurC.Round(time.Millisecond))
		fmt.Fprintf(w, "\n  Peak concurrent containers: %d\n", peak)
		fmt.Fprintf(w, "  Final active containers:    %d\n\n", active)
	}

	mu.Lock()
	sCopy := make([]scenarioTiming, len(scenarioList))
	copy(sCopy, scenarioList)
	mu.Unlock()

	if len(sCopy) > 0 {
		type featureAgg struct {
			Count int
			Total time.Duration
			Max   time.Duration
		}
		features := make(map[string]*featureAgg)
		for _, s := range sCopy {
			f := filepath.Base(s.Feature)
			agg, ok := features[f]
			if !ok {
				agg = &featureAgg{}
				features[f] = agg
			}
			agg.Count++
			agg.Total += s.Duration
			if s.Duration > agg.Max {
				agg.Max = s.Duration
			}
		}

		fNames := make([]string, 0, len(features))
		for f := range features {
			fNames = append(fNames, f)
		}
		sort.Strings(fNames)

		fmt.Fprintf(w, "--- Per-Feature Aggregate ---\n")
		fmt.Fprintf(w, "  %-35s %5s %10s %10s %10s\n", "FEATURE", "COUNT", "TOTAL", "AVG", "MAX")
		for _, f := range fNames {
			agg := features[f]
			avg := agg.Total / time.Duration(agg.Count)
			fmt.Fprintf(w, "  %-35s %5d %10s %10s %10s\n",
				f, agg.Count,
				agg.Total.Round(time.Millisecond), avg.Round(time.Millisecond),
				agg.Max.Round(time.Millisecond))
		}
		fmt.Fprintln(w)

		sort.Slice(sCopy, func(i, j int) bool {
			return sCopy[i].Duration > sCopy[j].Duration
		})
		limit := 20
		if len(sCopy) < limit {
			limit = len(sCopy)
		}
		fmt.Fprintf(w, "--- Top %d Longest Scenarios ---\n", limit)
		for i, s := range sCopy[:limit] {
			name := s.Name
			if len(name) > 55 {
				name = name[:52] + "..."
			}
			fmt.Fprintf(w, "  %2d. %-55s %10s  (%s)\n",
				i+1, name, s.Duration.Round(time.Millisecond), filepath.Base(s.Feature))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "==========================================\n")

	report := buf.String()
	fmt.Fprint(os.Stderr, report)

	if outputDir != "" {
		os.WriteFile(filepath.Join(outputDir, "report.txt"), []byte(report), 0644)
	}
	if outputFile != nil {
		outputFile.Close()
	}
}
