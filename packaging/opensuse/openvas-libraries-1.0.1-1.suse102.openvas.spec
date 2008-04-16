# OpenVAS
# $Id$
# Description: RPM spec file for openvas-libraries
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
#
# Copyright:
# Copyright (c) 2008 Intevation GmbH, http://www.intevation.de
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

%define PACKAGE_NAME openvas-libraries
%define PACKAGE_VERSION 1.0.1
%define release 1.suse102.openvas
%define _prefix /usr

Summary: Support libraries for Open Vulnerability Assessment (OpenVAS) Server
Name:    %PACKAGE_NAME
Version: %PACKAGE_VERSION
Release: %{release}
Source0: %{name}-%{version}.tar.gz
Patch0:  %{name}-%{version}-Makefile.diff
Patch1:  %{name}-%{version}-hg-Makefile.diff
License: GNU LGPLv2
Group: Productivity/Networking/Security
Vendor: OpenVAS Development Team, http://www.openvas.org 
Distribution: OpenSUSE 10.2
BuildRoot: %{_builddir}/%{name}-root
Prefix: %{_prefix}
BuildRequires: gnutls-devel
# TODO: refine: gnutls-devel works with >= 1.4.4, definitly not with 1.0.8

%package devel
Summary: Development files for openvas-libraries
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description
openvas-libraries is the base library for the OpenVAS network
security scanner.

%description devel
This package contains the development files (mainly C header files)
for openvas-libraries.

%prep
%setup -b 0
%patch0
%patch1

%build
%configure --prefix=%{_prefix}
make

%install
%makeinstall

%post
%{run_ldconfig}

%postun
%{run_ldconfig}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc INSTALL_README TODO libopenvas/COPYING 
%{_libdir}/lib*

%files devel
%defattr(-,root,root,-)
%{_includedir}/openvas/
%{_bindir}/libopenvas-config
%{_mandir}/man1/libopenvas-config.1.gz

%changelog
* Tue Apr 15 2008 Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
  Initial SUSE 10.2 spec file, tested for i586
