2140-dev/bitcoin
================

> [!WARNING]
> This software contains experimental features and is not recommended for general use. Run it at your own risk. We run this node ourselves to verify our experiments. We do not distribute binaries; you must build from source (see `doc/build-*.md`).


> [!NOTE]
> This repository is a fork of Bitcoin Core maintained by the [2140](https://2140.dev) team. It is a staging ground for bigger, more intrusive ideas that we develop end-to-end before proposing them upstream to [bitcoin/bitcoin](https://github.com/bitcoin/bitcoin). We take a move-fast-break-things approach to work through edge cases and validate ideas thoroughly.

This repository is not limited to the 2140 team; anyone is welcome to propose ideas and open pull requests here.

What is Bitcoin Core?
---------------------

Bitcoin Core connects to the Bitcoin peer-to-peer network to download and fully
validate blocks and transactions.

Further information about Bitcoin Core is available in the [doc folder](/doc).

License
-------

Bitcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/license/MIT.

Development Process
-------------------

The `master` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be completely stable.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is important; please help out by testing other people's pull requests. This is experimental software; changes may be unstable or incomplete.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled during the generation of the build system) with: `ctest`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

The CI (Continuous Integration) systems make sure that every pull request is tested on Linux and macOS.
The CI must pass on all commits before merge to avoid unrelated CI failures on new pull requests.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.
