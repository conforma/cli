# Acceptance tests

Acceptance tests are defined used [Cucumber](https://cucumber.io/) in
[Gherkin](https://cucumber.io/docs/gherkin/) syntax, the steps are implemented
in Go with the help of [Godog](https://github.com/cucumber/godog/).

Feature files written in Gherkin are kept in the [features](../../features/)
directory.

Entry point for the tests is the [acceptance_test.go](acceptance_test.go), which
uses the established Go test to launch Godog.

## Running

To run the acceptance tests either run:

    $ E2E_INSTRUMENTATION=true make acceptance

from the root of the repository.

Or move into the acceptance module:

    $ cd acceptance

and run the acceptance_test.go test using `go test`:

    $ go test ./...

The latter is useful for specifying additional arguments. Currently, the
following are supported:

  * `-persist` if specified the test environment will persist after test
    execution, making it easy to recreate test failures and debug the `ec`
    command line or acceptance test code
  * `-restore` run the tests against the persisted environment with `-persist`
  * `-no-colors` disable colored output, useful when running in a terminal that
    doesn't support color escape sequences
  * `-tags=...` comma separated tags to run, e.g. `@bugs` - to run only the
    scenarios tagged with `@bugs`, or `@bugs,~@wip` to run all scenarios that
    are tagged with `@bugs` but not with `@wip`

These arguments need to be prefixed with `-args` parameter, for example:

    $ go test ./acceptance -args -persist -tags=@focus

The `-tags` argument is for selecting acceptance test scenarios.

Also notice that there are different ways of specifying the path to the
acceptance tests. `./...` can only be be used if `-args` is NOT used. Use,
`./acceptance` or `github.com/conforma/cli/acceptance`
in such cases.

Depending on your setup Testcontainer's ryuk container might need to be run as
privileged container. For that, $HOME/.testcontainers.properties needs to be
created with:

    ryuk.container.privileged=true

Also, you will need to be able to run Docker without elevating the privileges,
that is as a non-root user. See the
[documentation](https://docs.docker.com/engine/install/linux-postinstall/) on
Docker website how to accomplish that.

## Debugging

The acceptance tests execute the `ec` binary during test execution. (For this
reason `E2E_INSTRUMENTATION=true make acceptance` builds the binary prior to running the tests.)

To use a debugger, like [delve](https://github.com/go-delve/delve), you must
determine what part of the code is being debugged. If it's part of the
acceptance module, `github.com/conforma/cli/acceptance`, or
it is a dependency of the acceptance module, then the debugger can be invoked
directly. However, if the code to be debugged is in any other module, first
run the acceptance tests in `-persist` mode. The, scan the test logs for the
exact command used during the test you want to debug. Finally, run the `ec` code
via the debugger, for example:

    dlv debug -- track bundle --bundle localhost:49167/acceptance/bundle:tag

## Creating acceptance tests

You can use the existing step implementations and add scenarios to existing or
new feature files. For any new steps Godog will print the function snippet that
needs to be implemented to support it. Please take care to refactor and extend
the functionality of existing step implementations and add new steps only when
existing steps are not sufficient. Keeping the acceptance test code well
organized and succinct/simple as it can be is the key to long term viability
and maintainablity of the acceptance tests.

Don't introduce dependencies on services not stubbed by the test environment.
We use [Testcontainers](https://www.testcontainers.org/) extensively to make
the test environment self-contained and deterministic. When using
Testcontainers, pass the `testcontainers.ContainerRequest` through
`testenv.TestContainersRequest` to make sure the `persist` flag is honored.

We use [WireMock](https://wiremock.org/) to stub HTTP APIs, such as Kuberetes
apiserver or Rekord.

Make sure not to introduce global state as this makes it difficult to run tests
concurrently. Running the acceptance tests concurrently is important for fast
feedback/turnaround. All state should be held in `context.Context`'s values.
Make sure that keys for those values are unique and package-private to prevent
dependencies from client packages on the `context.Context` state specific to
the implementation of the stub/helper.

When possible use the exact types (structs) for the API payloads and
(un)marshall to JSON/YAML at the edges of the stub. This helps with making the
payloads future-proof.

Pay attention to the `testenv.Persisted()` if the test is running whe the
`persisted` flag when cleaning up state that is needed to reproduce the test
failure.

Whenever possible include enough information in the test failure to make it
easy to reason about the context of the failure. Consider situations where
all that is available is the log output of the tests and the error message
from the test failure.

## Using snapshots

We use
[github.com/gkampitakis/go-snaps](https://github.com/gkampitakis/go-snaps) for
snapshotting mostly for asserting the standard error and output of the CLI with
the `the output should match the snapshot` step. The snapshots are placed in the
`features/__snapshots__` directory.

Sometimes the output changes and the snapshots need updating, this can be done
by setting `UPDATE_SNAPS=true` environment variable.

NOTE: If subset of features is run, there might be a message from the
snappshoting library that there are outdated snapshots, the cause of this might
be that the scenario generating the snapshot was not run.

## Known Issues

`context deadline exceeded: failed to start container` may occur in some
cases. `sudo systemctl restart docker` usually fixes it.

## Running on MacOS
Running on MacOS has been tested using podman machine. Listed below are the recommended
podman machine settings.
* Set rootful to true
  * `podman machine set --rootful=true`
* Set memory to 4GB
  * `podman machine set -m 4096`
* Set cpus to 2
  * `podman machine set --cpus 2`
* Disable selinux on the podman vm
  * `podman machine ssh`
  * `vi /etc/selinux/config`
  * Set `SELINUX=disable`
* Rename the default bridge in containers.conf
  * `podman machine ssh`
  * `vi /etc/containers/containers.conf`
  * Set `[network]
         default_network="bridge"`
* Restart the vm
  * `podman machine stop`
  * `podman machine start`
