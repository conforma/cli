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

package root

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"

	hd "github.com/MakeNowJust/heredoc/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/conforma/cli/internal/http"
	"github.com/conforma/cli/internal/kubernetes"
	"github.com/conforma/cli/internal/logging"
	"github.com/conforma/cli/internal/tracing"
)

var (
	quiet         bool          = false
	verbose       bool          = false
	debug         bool          = false
	enabledTraces tracing.Trace = tracing.None
	globalTimeout               = 5 * time.Minute
	logfile       string

	// Retry configuration flags
	retryMaxWait  time.Duration = 3 * time.Second
	retryMaxRetry int           = 3
	retryDuration time.Duration = 1 * time.Second
	retryFactor   float64       = 2.0
	retryJitter   float64       = 0.1

	OnExit func() = func() {}
)

type customDeadlineExceededError struct{}

func (customDeadlineExceededError) Error() string {
	return fmt.Sprintf("exceeded allowed execution time of %s, the timeout can be adjusted using the --timeout command line argument", globalTimeout)
}
func (customDeadlineExceededError) Timeout() bool   { return true }
func (customDeadlineExceededError) Temporary() bool { return true }

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ec",
		Short: "Conforma CLI",

		Long: hd.Doc(`
			Conforma CLI

			Secure your software supply chain by validating that your artifacts meet security and 
			compliance requirements. Conforma helps you verify the authenticity and integrity of 
			container images, build processes, and deployment pipelines.

			Whether you're ensuring images are properly signed, validating build attestations comply 
			with your organization's policies, or checking that Tekton tasks follow security best 
			practices, Conforma provides the tools you need to establish trust in your software 
			delivery process.

			Key capabilities:
			• Verify signatures and attestations on container images
			• Validate SLSA provenance to ensure secure build processes  
			• Enforce compliance policies across your development workflow
			• Generate detailed reports for audit and compliance purposes
			• Support for custom validation rules to meet your specific requirements

			Use Conforma to implement "trust but verify" practices in your CI/CD pipeline, 
			ensuring that only secure, compliant artifacts make it to production.

			Have feedback or want to contribute? Visit https://conforma.dev/contribute/ to join our 
			community, report issues, or help improve Conforma.
		`),

		SilenceUsage: true,

		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			logging.InitLogging(verbose, quiet, debug, enabledTraces.Enabled(tracing.Log, tracing.Opa), logfile)

			// Apply retry configuration from CLI flags
			retryConfig := http.RetryConfig{
				MaxWait:  retryMaxWait,
				MaxRetry: retryMaxRetry,
				Duration: retryDuration,
				Factor:   retryFactor,
				Jitter:   retryJitter,
			}
			http.SetRetryConfig(retryConfig)

			// set a custom message for context.DeadlineExceeded error
			context.DeadlineExceeded = customDeadlineExceededError{}

			// Create a new context now that flags have been parsed so a
			// custom timeout can be used and traces can be added
			ctx := cmd.Context()
			var cancel context.CancelFunc
			if globalTimeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, globalTimeout)
				log.Debugf("globalTimeout is %s", time.Duration(globalTimeout))
			} else {
				log.Debugf("globalTimeout is %d, no timeout used", globalTimeout)
			}
			ctx = tracing.WithTrace(ctx, enabledTraces)
			cmd.SetContext(ctx)

			var cpuprofile *os.File
			var tracefile *os.File
			if enabledTraces.Enabled(tracing.CPU) {
				var err error
				if cpuprofile, err = os.CreateTemp("", "cpuprofile.*"); err != nil {
					log.Fatalf("could not create CPU profile: %v", err)
				}
				if err := pprof.StartCPUProfile(cpuprofile); err != nil {
					log.Fatalf("could not start CPU profile: %v", err)
				}
			}

			if enabledTraces.Enabled(tracing.Perf) {
				var err error
				if tracefile, err = os.CreateTemp("", "perf.*"); err != nil {
					log.Fatalf("could not create trace file: %v", err)
				}
				if err := trace.Start(tracefile); err != nil {
					log.Fatalf("failed to start trace: %v", err)
				}
			}

			OnExit = sync.OnceFunc(func() {
				if enabledTraces.Enabled(tracing.Memory) {
					// dump memory profile
					if memprofile, err := os.CreateTemp("", "memprofile.*"); err != nil {
						log.Fatal("could not create memory profile: ", err)
					} else {
						defer memprofile.Close()
						if err := pprof.WriteHeapProfile(memprofile); err != nil {
							log.Fatal("could not start CPU profile: ", err)
						}

						cmd.PrintErrf("Wrote memory profile to: %s\n", memprofile.Name())
					}
				}

				if enabledTraces.Enabled(tracing.CPU) {
					// dump the CPU profile
					pprof.StopCPUProfile()
					if cpuprofile != nil {
						_ = cpuprofile.Close() // ignore errors
						cmd.PrintErrf("Wrote CPU profile to: %s\n", cpuprofile.Name())
					}
				}

				if enabledTraces.Enabled(tracing.Perf) {
					trace.Stop()
					if tracefile != nil {
						_ = tracefile.Close() // ignore errors
						cmd.PrintErrf("Wrote performance trace to: %s\n", tracefile.Name())
					}
				}

				// perform resource cleanup
				if f, ok := log.StandardLogger().Out.(io.Closer); ok {
					f.Close()
				}
				if cancel != nil {
					cancel()
				}
			})
		},
	}

	setFlags(rootCmd)

	return rootCmd
}

func setFlags(rootCmd *cobra.Command) {
	traceFlag := &pflag.Flag{
		Name:        "trace",
		Usage:       "enable trace logging, set one or more comma separated values: none,all," + tracing.All.String(),
		Value:       &enabledTraces,
		DefValue:    enabledTraces.String(),
		NoOptDefVal: tracing.Default.String(),
	}
	rootCmd.PersistentFlags().AddFlag(traceFlag)

	rootCmd.PersistentFlags().BoolVar(&quiet, "quiet", quiet, "less verbose output")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", verbose, "more verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", debug, "same as verbose but also show function names and line numbers")
	rootCmd.PersistentFlags().DurationVar(&globalTimeout, "timeout", globalTimeout, "max overall execution duration")
	rootCmd.PersistentFlags().StringVar(&logfile, "logfile", "", "file to write the logging output. If not specified logging output will be written to stderr")

	// Retry configuration flags
	rootCmd.PersistentFlags().DurationVar(&retryMaxWait, "retry-max-wait", retryMaxWait, "maximum wait time between retries")
	rootCmd.PersistentFlags().IntVar(&retryMaxRetry, "retry-max-retry", retryMaxRetry, "maximum number of retry attempts")
	rootCmd.PersistentFlags().DurationVar(&retryDuration, "retry-duration", retryDuration, "base duration for exponential backoff calculation")
	rootCmd.PersistentFlags().Float64Var(&retryFactor, "retry-factor", retryFactor, "exponential backoff multiplier")
	rootCmd.PersistentFlags().Float64Var(&retryJitter, "retry-jitter", retryJitter, "randomness factor for backoff calculation (0.0-1.0)")

	kubernetes.AddKubeconfigFlag(rootCmd)
}
