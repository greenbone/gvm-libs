# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [20.8.1] (2021-02-01)

### Added
- Add function to get duplicated hosts from the hosts list. [#387](https://github.com/greenbone/gvm-libs/pull/387)
- Add file access tests using effective UID/GID [#422](https://github.com/greenbone/gvm-libs/pull/422)

### Changed
- Reduce ping timeout when using test_alive_hosts_only feature. [#400](https://github.com/greenbone/gvm-libs/pull/400)
- Retry if response via tls1.3 is still not received. [#404](https://github.com/greenbone/gvm-libs/pull/404)

### Fixed
- Fix port list for tcp pings when using test_alive_hosts_only feature. [#392](https://github.com/greenbone/gvm-libs/pull/392)
- Set source address correctly and do not try to send ARP to unreachable destination. [#401](https://github.com/greenbone/gvm-libs/pull/401)
- Increase minimum gpgme version [#405](https://github.com/greenbone/gvm-libs/pull/405)
- Always NULL check ifaddrs->ifa_addr [#416](https://github.com/greenbone/gvm-libs/pull/416)
- Correct g_hash_table_remove arg [#419](https://github.com/greenbone/gvm-libs/pull/419)
- Accept underscore as valid char in hostname strings [#430](https://github.com/greenbone/gvm-libs/pull/430)
- Add throttle for pinging with test_alive_hosts_only feature when socket buffer is full. [#429](https://github.com/greenbone/gvm-libs/pull/429)

[20.8.1]: https://github.com/greenbone/gvm-libs/compare/v20.8.0...v20.8.1

## [20.8.0] (2020-08-12)

### Added
- Add nvti_get_tag() [#285](https://github.com/greenbone/gvm-libs/pull/285)
- Add nvti_solution_method() and nvti_set_solution_method() [#283](https://github.com/greenbone/gvm-libs/pull/283)
- Extend osp with target's alive test option.[#312](https://github.com/greenbone/gvm-libs/pull/312)
- Extend osp with target's reverse_lookup_* options.[#314](https://github.com/greenbone/gvm-libs/pull/314)
- Add unit tests for osp. [#315](https://github.com/greenbone/gvm-libs/pull/315)
- Add support for test_alive_hosts_only feature of openvas. [#320](https://github.com/greenbone/gvm-libs/pull/320)
- Add function to set and get the NVT QoD. [#321](https://github.com/greenbone/gvm-libs/pull/321)
- Add unit tests for networking.c port list functions. [#325](https://github.com/greenbone/gvm-libs/pull/325)
- Add gmp_start_task_ext_c. [#327](https://github.com/greenbone/gvm-libs/pull/327)
- Make log mutex visible. [#328](https://github.com/greenbone/gvm-libs/pull/328)
- Add new scan status QUEUED.
  [#336](https://github.com/greenbone/gvm-libs/pull/336)
  [#340](https://github.com/greenbone/gvm-libs/pull/340)
- Add gvm_routethrough which is used by Boreas alive detection module. [#339](https://github.com/greenbone/gvm-libs/pull/339)
- Move alive detection module Boreas into gvm-libs. [#346](https://github.com/greenbone/gvm-libs/pull/346)
- Add new scan status INTERRUPTED. [#356](https://github.com/greenbone/gvm-libs/pull/356)
- Add sensible default values for osp_get_vts_opts_t. [#360](https://github.com/greenbone/gvm-libs/pull/360)
- Add cli support for boreas standalone tool. [#359](https://github.com/greenbone/gvm-libs/pull/359)

### Changed
- Improve validation in is_hostname [#353](https://github.com/greenbone/gvm-libs/pull/353)
- Use get_vts instead of get_version to get the feed version is osp_get_vts_version(). [#357](https://github.com/greenbone/gvm-libs/pull/357)
- Allow all alive test combination for boreas. [#370](https://github.com/greenbone/gvm-libs/pull/370)

### Fixed
- Fix is_cidr_block(). [#322](https://github.com/greenbone/gvm-libs/pull/322)
- Fix is_cidr6_block() and is_short_range_network(). [#337](https://github.com/greenbone/gvm-libs/pull/337)
- Fix S/MIME keylist and improve error handling [#345](https://github.com/greenbone/gvm-libs/pull/345)
- Fix interrupted state by sending correct number of dead hosts. [#371](https://github.com/greenbone/gvm-libs/pull/371)

### Removed
- Remove parallel from target options [#347](https://github.com/greenbone/gvm-libs/pull/347)
- Remove zero padding from version [#377](https://github.com/greenbone/gvm-libs/pull/377)

[20.8.0]: https://github.com/greenbone/gvm-libs/compare/v11.0.0...v20.8.0

## [11.0.1] (2020-05-12)

### Added
- Add option to set finished hosts in OSP targets [#298](https://github.com/greenbone/gvm-libs/pull/298)
- Add a fast memory-only XML parser [#299](https://github.com/greenbone/gvm-libs/pull/299)
- Add new function gvm_libs_version [#301](https://github.com/greenbone/gvm-libs/pull/301)

### Changed
- Don't create an entity tree during read_string_c. [#305](https://github.com/greenbone/gvm-libs/pull/305)

### Fixed
- Fix sigsegv when no plugin_feed_info.inc file present. [#278](https://github.com/greenbone/gvm-libs/pull/278)
- Fix missing linking to libgnutls in util/CMakeLists.txt. [#291](https://github.com/greenbone/gvm-libs/pull/291)
- Free string in all error exit cases [#308](https://github.com/greenbone/gvm-libs/pull/308)
- Fix trust and file handling for S/MIME [#309](https://github.com/greenbone/gvm-libs/pull/309)
- Get details with get_reports in gmp_get_report_ext [#313](https://github.com/greenbone/gvm-libs/pull/313)
- Fix escaping entity attributes in print_entity_to_string [#318](https://github.com/greenbone/gvm-libs/pull/318)
- Fix is_cidr_block() [#323](https://github.com/greenbone/gvm-libs/pull/323)
- Fix is_cidr6_block() and is_short_range_network(). [#338](https://github.com/greenbone/gvm-libs/pull/338)

[11.0.1]: https://github.com/greenbone/gvm-libs/compare/v11.0.0...v11.0.1

## [11.0.0] (2019-10-11)

### Added
- Allow to configure the path to the redis socket via CMake [#256](https://github.com/greenbone/gvm-libs/pull/256)
- A new data model for unified handling of cross references in the NVT meta data as been added. All previous API elements to handle cve, bid, xref have been removed. [#225](https://github.com/greenbone/gvm-libs/pull/225) [#232](https://github.com/greenbone/gvm-libs/pull/232).
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
- Disable testhosts test as it's not really a test. [#287](https://github.com/greenbone/gvm-libs/pull/287)
- Don't create an entity tree during read_string_c. [#305](https://github.com/greenbone/gvm-libs/pull/305)

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
