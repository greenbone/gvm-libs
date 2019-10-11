# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [11.0.0] (2019-10-11)

### Added
- Allow to configure the path to the redis socket via CMake [#256](https://github.com/greenbone/gvm-libs/pull/256)
- A new data model for unified handling of cross references in the NVT meta data as been added. All previous API elements to handle cve, bid, xref werehas been removed. [#225](https://github.com/greenbone/gvm-libs/pull/225) [#232](https://github.com/greenbone/gvm-libs/pull/232).
- Add function to get an osp scan status and a enum type for the different status [#259](https://github.com/greenbone/gvm-libs/pull/259)
- API functions for NVTI to handle timestamps [#261](https://github.com/greenbone/gvm-libs/pull/261)
- API function for NVTI to add a single tag [#263](https://github.com/greenbone/gvm-libs/pull/263)
- Add osp_get_performance_ext() function. [#262](https://github.com/greenbone/gvm-libs/pull/262)
- Add libldap2-dev to prerequisites. [#249](https://github.com/greenbone/gvm-libs/pull/249)
- Add function osp_get_vts_filtered(). [#251](https://github.com/greenbone/gvm-libs/pull/251)
- Add explicit attributes in nvti struct. [#258](https://github.com/greenbone/gvm-libs/pull/258)

### Changed
- Change the default path to the redis socket to /run/redis/redis.sock [#256](https://github.com/greenbone/gvm-libs/pull/256)
- Handle EAI_AGAIN in gvm_host_reverse_lookup() IPv6 case and function refactor. [#229](https://github.com/greenbone/gvm-libs/pull/229)
- Prevent g_strsplit to be called with NULL. [#238](https://github.com/greenbone/gvm-libs/pull/238)
- Timestamps for NVTI modification date and creation date now internally handled as seconds since epoch. [#265](https://github.com/greenbone/gvm-libs/pull/265)
- The tag cvss_base is not added to redis anymore. [#267](https://github.com/greenbone/gvm-libs/pull/267)
- Functions in osp.c with error as argument, will set the error if the connection is missing. [#268](https://github.com/greenbone/gvm-libs/pull/268)
- Make QoD Type an explicit element of struct nvti. [#250](https://github.com/greenbone/gvm-libs/pull/250)
- Use API to access nvti information. [#252](https://github.com/greenbone/gvm-libs/pull/252)
- Make the nvti struct internal. [#253](https://github.com/greenbone/gvm-libs/pull/253)
- Make solution and solution_type explicit for nvti. [#255](https://github.com/greenbone/gvm-libs/pull/255)
- Internalize struct nvtpref_t. [#260](https://github.com/greenbone/gvm-libs/pull/260)
- Extend redis connection error msg with actual path. [#264](https://github.com/greenbone/gvm-libs/pull/264)

### Fixed
- Prevent g_strsplit to be called with NULL. [#238](https://github.com/greenbone/gvm-libs/pull/238)
- Check filter before using it in osp_get_vts_ext. [#266](https://github.com/greenbone/gvm-libs/pull/266)

### Removed
- Remove inconsistent delays in kb routines. [#230](https://github.com/greenbone/gvm-libs/pull/230)

[11.0.0]: https://github.com/greenbone/gvm-libs/compare/v10.0.1...v11.0.0

## [10.0.1] (2019-07-17)

### Added
- Allow multiple certificate formats for S/MIME. [#231](https://github.com/greenbone/gvm-libs/pull/231)
- Add cmake options to build with ldap and radius support. [#235](https://github.com/greenbone/gvm-libs/pull/235)

### Changed
- Always add hostnames and vhosts in lower-case format. [#218](https://github.com/greenbone/gvm-libs/pull/218)
- Plugin feed version file: Show message only once if it is not found. [#220](https://github.com/greenbone/gvm-libs/pull/220)
- Use g_log instead of g_debug for No redis DB available message. [#224](https://github.com/greenbone/gvm-libs/pull/224)

### Fixed
- Fix prefs key in nvticache_delete(). [#214](https://github.com/greenbone/gvm-libs/pull/214)
- Fix redis_find(). [#216](https://github.com/greenbone/gvm-libs/pull/216)
- Fixes to gvm_hosts_resolve(). [#228](https://github.com/greenbone/gvm-libs/pull/228)

[10.0.1]: https://github.com/greenbone/gvm-libs/compare/v10.0.0...gvm-libs-10.0

## [10.0.0] (2019-04-05)

### Changed
- The function gvm_hosts_shuffle has been improved. [#200](https://github.com/greenbone/gvm-libs/pull/200)

### Fixed
- An issue which caused duplicated or removed values in the nvticache as addressed. [#196](https://github.com/greenbone/gvm-libs/pull/196)
- Performance fixes related to handling large sets of hosts have been done.[203](https://github.com/greenbone/gvm-libs/pull/203) [#208](https://github.com/greenbone/gvm-libs/pull/208)
- Memory management issues have been addressed. [#187](https://github.com/greenbone/gvm-libs/pull/187)


[10.0.0]: https://github.com/greenbone/gvm-libs/compare/1.0.0...v10.0.0
