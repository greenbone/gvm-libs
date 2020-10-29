![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# gvm-libs

[![GitHub releases](https://img.shields.io/github/release/greenbone/gvm-libs.svg)](https://github.com/greenbone/gvm-libs/releases)
[![Code Documentation Coverage](https://img.shields.io/codecov/c/github/greenbone/gvm-libs.svg?label=Doc%20Coverage&logo=codecov)](https://codecov.io/gh/greenbone/gvm-libs)
[![CircleCI](https://circleci.com/gh/greenbone/gvm-libs/tree/master.svg?style=svg)](https://circleci.com/gh/greenbone/gvm-libs/tree/master)

This is the libraries module for the Greenbone Vulnerability Management Solution.

It is used for the Greenbone Security Manager appliances and provides various
functionalities to support the integrated service daemons.

## Releases
￼
All [release files](https://github.com/greenbone/gvm-libs/releases) are signed with
the [Greenbone Community Feed integrity key](https://community.greenbone.net/t/gcf-managing-the-digital-signatures/101).
This gpg key can be downloaded at https://www.greenbone.net/GBCommunitySigningKey.asc
and the fingerprint is `8AE4 BE42 9B60 A59B 311C  2E73 9823 FAA6 0ED1 E580`.

## Installation

This module can be configured, built and installed with following commands:

    cmake .
    make install

For detailed installation requirements and instructions, please see the file
[INSTALL.md](INSTALL.md).

If you are not familiar or comfortable building from source code, we recommend
that you use the Greenbone Security Manager TRIAL (GSM TRIAL), a prepared virtual
machine with a readily available setup. Information regarding the virtual machine
is available at <https://www.greenbone.net/en/testnow>.

## Usage

The `gvm-libs` module consists of the following libraries:

- `base`: All basic modules which require only the `glib` library as a dependency.

- `util`: All modules that require more than the `glib` library as dependency.

- `gmp`: API support for the Greenbone Management Protocol (GMP).

- `osp`: API support for the Open Scanner Protocol (OSP).

For more information on using the functionality provided by the `gvm-libs`
module please refer to the source code documentation.

## Support

For any question on the usage of `gvm-libs` please use the [Greenbone Community
Portal](https://community.greenbone.net/c/gse). If you found a problem with the
software, please [create an issue](https://github.com/greenbone/gvm-libs/issues)
on GitHub. If you are a Greenbone customer you may alternatively or additionally
forward your issue to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone Networks GmbH](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/gvm-libs/pulls) on GitHub. Bigger changes
need to be discussed with the development team via the [issues section at
github](https://github.com/greenbone/gvm-libs/issues) first.

### Code style and formatting

Before creating a pull request, it is recommended to run the following command:

    make format

This reformats the new code to ensure that it follows the code style and
formatting guidelines.

### Static code analysis with the Clang Static Analyzer

If you want to use the Clang Static Analyzer (http://clang-analyzer.llvm.org/)
to do a static code analysis, you can do so by prefixing the configuration and
build commands with `scan-build`:

    scan-build cmake ..
    scan-build make

The tool will provide a hint on how to launch a web browser with the results.

It is recommended to do this analysis in a separate, empty build directory and
to empty the build directory before `scan-build` call.

## License

Copyright (C) 2009-2019 [Greenbone Networks GmbH](https://www.greenbone.net/)

Licensed under the [GNU General Public License v2.0 or later](COPYING).
