# Unit tests

The sources in this directory are unit test cases. Tests use a small
header-only framework declared in `src/test/util/framework.hpp`, which
provides registration macros (`TEST_CASE`, `FIXTURE_TEST_CASE`,
`TEST_SUITE_BEGIN`/`TEST_SUITE_END`) and assertion macros (`CHECK`,
`REQUIRE`, `CHECK_THROWS`, `CHECK_THROWS_AS`, `CHECK_EXCEPTION`,
`CHECK_EQUAL_RANGES`, `TEST_MESSAGE`, `WARN_MESSAGE`).

The build system is set up to compile an executable called `test_bitcoin`
that runs all of the unit tests. The main source file for the test library is found in
`util/setup_common.cpp`.

The examples in this document assume the build directory is named
`build`. You'll need to adapt them if you named it differently.

### Compiling/running unit tests

Unit tests will be automatically compiled if dependencies were met
during the generation of the Bitcoin Core build system
and tests weren't explicitly disabled.

The unit tests can be run with `ctest --test-dir build`, which includes unit
tests from subtrees.

Run `build/bin/test_bitcoin --list` for the full list of tests.

To run the unit tests manually, launch `build/bin/test_bitcoin`. To recompile
after a test file was modified, run `cmake --build build` and then run the test again. If you
modify a non-test file, use `cmake --build build --target test_bitcoin` to recompile only what's needed
to run the unit tests.

To add more unit tests, add `TEST_CASE` (or `FIXTURE_TEST_CASE`) functions to
the existing .cpp files in the `test/` directory, or add new .cpp files that
declare a new suite with `TEST_SUITE_BEGIN("<name>")`.

### Running individual tests

To see the list of arguments that may be passed, run:

```
build/bin/test_bitcoin --help
```

For example, to run only the tests in the `getarg_tests` suite, with full logging:

```bash
build/bin/test_bitcoin --log_level=all --run_test=getarg_tests
```

or

```bash
build/bin/test_bitcoin -l all -t getarg_tests
```

or to run only the `doubledash` test in `getarg_tests`

```bash
build/bin/test_bitcoin --run_test=getarg_tests::doubledash
```

The `--log_level=` (or `-l`) argument controls the verbosity of the test output.
Accepted values: `none`, `error` (default), `info`, `all`.

The `test_bitcoin` runner also accepts some of the command line arguments accepted by
`bitcoind`. Use `--` to separate these sets of arguments:

```bash
build/bin/test_bitcoin --log_level=all --run_test=getarg_tests -- -printtoconsole=1
```

The `-printtoconsole=1` after the two dashes sends debug logging, which
normally goes only to `debug.log` within the data directory, to the
standard terminal output as well.

Running `test_bitcoin` creates a temporary working (data) directory with a randomly
generated pathname within `test_common bitcoin/`, which in turn is within
the system's temporary directory (see
[`temp_directory_path`](https://en.cppreference.com/w/cpp/filesystem/temp_directory_path)).
This data directory looks like a simplified form of the standard `bitcoind` data
directory. Its content will vary depending on the test, but it will always
have a `debug.log` file, for example.

The location of the temporary data directory can be specified with the
`-testdatadir` option. This can make debugging easier. The directory
path used is the argument path appended with
`/test_common bitcoin/<test-name>/datadir`.
The directory path is created if necessary.
Specifying this argument also causes the data directory
not to be removed after the last test. This is useful for looking at
what the test wrote to `debug.log` after it completes, for example.
(The directory is removed at the start of the next test run,
so no leftover state is used.)

```bash
$ build/bin/test_bitcoin --run_test=getarg_tests/doubledash -- -testdatadir=/somewhere/mydatadir
Test directory (will not be deleted): "/somewhere/mydatadir/test_common bitcoin/getarg_tests/doubledash/datadir"
Running 1 test case...

*** No errors detected
$ ls -l '/somewhere/mydatadir/test_common bitcoin/getarg_tests/doubledash/datadir'
total 8
drwxrwxr-x 2 admin admin 4096 Nov 27 22:45 blocks
-rw-rw-r-- 1 admin admin 1003 Nov 27 22:45 debug.log
```

If you run an entire test suite, such as `--run_test=getarg_tests`, or all the test suites
(by not specifying `--run_test`), a separate directory
will be created for each individual test.

### Adding test cases

To add a new unit test file to our test suite, you need
to add the file to either `src/test/CMakeLists.txt` or
`src/wallet/test/CMakeLists.txt` for wallet-related tests. The pattern is to create
one test file for each class or source file for which you want to create
unit tests. The file naming convention is `<source_filename>_tests.cpp`
and such files should wrap their tests in a test suite
called `<source_filename>_tests`. For an example of this pattern,
see `uint256_tests.cpp`.

### Logging and debugging in unit tests

`ctest --test-dir build` will write to the log file `build/Testing/Temporary/LastTest.log`. You can
additionally use the `--output-on-failure` option to display logs of the failed tests automatically
on failure. For running individual tests verbosely, refer to the section
[above](#running-individual-tests).

To write a diagnostic message from a unit test, use `TEST_MESSAGE(...)`
(emitted at log level `info` or higher). `WARN_MESSAGE(cond, msg)` emits
a warning when `cond` is false without failing the test — use `CHECK` /
`REQUIRE` to fail.

For debugging you can launch the `test_bitcoin` executable with `gdb` or `lldb` and
start debugging, just like you would with any other program:

```bash
gdb build/bin/test_bitcoin
```

#### Segmentation faults

If you hit a segmentation fault during a test run, you can diagnose where the fault
is happening by running `gdb ./build/bin/test_bitcoin` and then using the `bt` command
within gdb.

Another tool that can be used to resolve segmentation faults is
[valgrind](https://valgrind.org/).

If for whatever reason you want to produce a core dump file for this fault, you can do
that as well. Ensure that your ulimits are set properly (e.g. `ulimit -c unlimited`),
then running the tests and hitting a segmentation fault should produce a file called
`core` (on Linux platforms, the file name will likely depend on the contents of
`/proc/sys/kernel/core_pattern`).

You can then explore the core dump using
```bash
gdb build/bin/test_bitcoin core

(gdb) bt  # produce a backtrace for where a segfault occurred
```
