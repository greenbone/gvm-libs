![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# gvm-libs <!-- omit in toc -->

[![GitHub releases](https://img.shields.io/github/release/greenbone/gvm-libs.svg)](https://github.com/greenbone/gvm-libs/releases)
[![Build and test C](https://github.com/greenbone/gvm-libs/actions/workflows/ci-c.yml/badge.svg)](https://github.com/greenbone/gvm-libs/actions/workflows/ci-c.yml)
[![codecov](https://codecov.io/gh/greenbone/gvm-libs/graph/badge.svg?token=OUojGTMBgP)](https://codecov.io/gh/greenbone/gvm-libs)

This is the libraries module for the Greenbone Community Edition.

It is used for the Greenbone Enterprise appliances and provides various
functionalities to support the integrated service daemons.

- [Releases](#releases)
- [Installation](#installation)
- [Usage](#usage)
- [Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
  - [Code style and formatting](#code-style-and-formatting)
  - [CMake formatting](#cmake-formatting)
  - [Static code analysis with the Clang Static Analyzer](#static-code-analysis-with-the-clang-static-analyzer)
- [License](#license)

## Releases

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
Portal](https://community.greenbone.net/). If you found a problem with the
software, please [create an issue](https://github.com/greenbone/gvm-libs/issues)
on GitHub. If you are a Greenbone customer you may alternatively or additionally
forward your issue to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone AG](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/gvm-libs/pulls) on GitHub. Bigger changes
need to be discussed with the development team via the [issues section at
github](https://github.com/greenbone/gvm-libs/issues) first.

Before creating a pull request, it is recommended to check the formatting for
source code and cmake files.

### Code style and formatting

All C source and header files are formatted using [clang-format](https://clang.llvm.org/docs/ClangFormat.html).
To install clang-format on a Debian based system the following command can be
used:

    sudo apt install clang-format

To format all C source and header files run the command:

    make format

This reformats the new code to ensure that it follows the code style and
formatting guidelines.

### CMake formatting

All CMake files are formatted using [gersemi](https://github.com/BlankSpruce/gersemi).
To install gersemi on a Debian based system the following commands can be used:

    sudo apt install pipx
    pipx install gersemi

To format all CMake files run the command:

    gersemi -i cmake .

### Static code analysis with the Clang Static Analyzer

If you want to use the [Clang Static Analyzer](http://clang-analyzer.llvm.org/)
to do a static code analysis, you can do so by prefixing the configuration and
build commands with `scan-build`:

    scan-build cmake ..
    scan-build make

The tool will provide a hint on how to launch a web browser with the results.

It is recommended to do this analysis in a separate, empty build directory and
to empty the build directory before `scan-build` call.

## License

Copyright (C) 2009-2026 [Greenbone AG](https://www.greenbone.net/)

Licensed under the [GNU General Public License v2.0 or later](COPYING).
