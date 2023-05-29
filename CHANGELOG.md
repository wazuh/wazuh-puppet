# Change Log
All notable changes to this project will be documented in this file.

## Wazuh Puppet v4.4.3

### Added

- Support to 4.4.3 Wazuh release.

## Wazuh Puppet v4.4.2

### Added

- Support to 4.4.2 Wazuh release.

## Wazuh Puppet v4.4.1

### Added

- Support to 4.4.1 Wazuh release.

## Wazuh Puppet v4.4.0

### Added

- Support to 4.4.0 Wazuh release.

## Wazuh Puppet v4.3.11

### Added

- Support to 4.3.11 Wazuh release.

## Wazuh Puppet v4.3.10

### Added

- Support to 4.3.10 Wazuh release.

## Wazuh Puppet v4.3.9

### Added

- Support to 4.3.9 Wazuh release.

## Wazuh Puppet v4.3.8

### Added

- Support to 4.3.8 Wazuh release.

## Wazuh Puppet v4.3.7

### Added

- Support to 4.3.7 Wazuh release.

## Wazuh Puppet v4.3.6

### Added

- Support to 4.3.6 Wazuh release.

## Wazuh Puppet v4.3.5

### Added

- Support to 4.3.5 Wazuh release.

## Wazuh Puppet v4.3.4

### Added

- Support to 4.3.4 Wazuh release.

## Wazuh Puppet v4.3.3

### Added

- Support to 4.3.3 Wazuh release.

## Wazuh Puppet v4.3.2

### Added

- Support to 4.3.2 Wazuh release.

## Wazuh Puppet v4.3.1

### Added

- Support to 4.3.1 Wazuh release.

## Wazuh Puppet v4.3.0

### Added

- Support to 4.3.0 Wazuh release.

## Wazuh Puppet v4.2.7

### Added

- Support to 4.2.7 Wazuh release.

## Wazuh Puppet v4.2.6

### Added

- Support to 4.2.6 Wazuh release.

## Wazuh Puppet v4.2.5

### Added

- Support to 4.2.5 Wazuh release.

## Wazuh Puppet v4.2.4

### Added

- Support to 4.2.4 Wazuh release.

## Wazuh Puppet v4.2.3

### Added

- Support to 4.2.3 Wazuh release.

## Wazuh Puppet v4.2.2

### Added

- Support to 4.2.2 Wazuh release.

### Fixed

- Fixed a bug in the agent.pp manifest that prevented the Wazuh Agent from upgrading in Windows ([#374](https://github.com/wazuh/wazuh-puppet/issues/374))

## Wazuh Puppet v4.2.1

### Added

- Support to 4.2.1 Wazuh release.

## Wazuh Puppet v4.2.0

### Added

- Support to 4.2.0 Wazuh release.

## Wazuh Puppet v4.1.5

### Added

- Support to 4.1.5 Wazuh release.

## Wazuh Puppet v4.0.4

### Added

- Update to Wazuh [v4.0.4](https://github.com/wazuh/wazuh-ansible/blob/v4.0.4/CHANGELOG.md)
- Add support for Elasticsearch cluster in Kibana manifests  ([@neonmei](https://github.com/neonmei)) [PR#317](https://github.com/wazuh/wazuh-puppet/pull/317)
- Add support for Ubuntu 20.04 (Focal Fossa)  ([@Zenidd](https://github.com/Zenidd), [@neonmei](https://github.com/neonmei)) [PR#321](https://github.com/wazuh/wazuh-puppet/pull/321)
### Fixed

- Idempotency improvements in Elasticsearch manifests  ([@neonmei](https://github.com/neonmei)) [PR#313](https://github.com/wazuh/wazuh-puppet/pull/313)
- Linting improvements work for Puppet Forge publishing  ([@Zenidd](https://github.com/Zenidd)) [PR#314](https://github.com/wazuh/wazuh-puppet/pull/314)
- Idempotency improvements in Kibana manifests  ([@neonmei](https://github.com/neonmei)) [PR#315](https://github.com/wazuh/wazuh-puppet/pull/315)
- PDK validate improvements  ([@neonmei](https://github.com/neonmei)) [PR#319](https://github.com/wazuh/wazuh-puppet/pull/319)
- Fix warnings due to undefined variables  ([@Hexta](https://github.com/Hexta)) [PR#331](https://github.com/wazuh/wazuh-puppet/pull/331)
-  Use `manager_ossec.conf` as render target for Integrations  ([@Zenidd](https://github.com/Zenidd)) [PR#327](https://github.com/wazuh/wazuh-puppet/pull/327)
-  Use `manager_ossec.conf` as render target for Reports  ([@Zenidd](https://github.com/Zenidd)) [PR#328](https://github.com/wazuh/wazuh-puppet/pull/328)
-  Remove manager-specific options for active response in agent manifest  ([@Zenidd](https://github.com/Zenidd)) [PR#332](https://github.com/wazuh/wazuh-puppet/pull/332)
-  Fix stdlib deprecation warnings related to `validate_*` functions ([@Hexta](https://github.com/Hexta)) [PR#334](https://github.com/wazuh/wazuh-puppet/pull/334)
-  Update target name in concat resources for `manager_ossec.conf`  ([@g3rhard](https://github.com/g3rhard )) [PR#341](https://github.com/wazuh/wazuh-puppet/pull/341)

## Wazuh Puppet v4.0.3

### Added

- Update to Wazuh version 4.0.3

### Fixed

- Templates: update jvm.options template with version information  ([@neonmei](https://github.com/neonmei)) [PR#310](https://github.com/wazuh/wazuh-puppet/pull/310)
- Restart manager service after modifying agent_auth_password  ([@Fabian1976](https://github.com/Fabian1976)) [PR#307](https://github.com/wazuh/wazuh-puppet/pull/307)


## Wazuh Puppet v4.0.2

### Added

- Update to Wazuh version 4.0.2

### Fixed

- Syscheck 'report_changes' option ([@oletos7j](https://github.com/oletos7j)) [PR#306](https://github.com/wazuh/wazuh-puppet/pull/306)


## Wazuh Puppet v4.0.1

### Added

- Update to Wazuh version 4.0.1
- Support for Wazuh v4 new features ([@Zenidd](https://github.com/Zenidd)) [PR#300](https://github.com/wazuh/wazuh-puppet/pull/300):
  - Agent autoenrollment
  - API RBAC


## Wazuh Puppet v3.13.2

### Added

- Update to Wazuh version 3.13.2

- wazuh-puppet tests on GitHub Actions ([@Zenidd](https://github.com/Zenidd)) [PR#274](https://github.com/wazuh/wazuh-puppet/pull/274)

- Support Open Distro for Elasticsearch deployments ([@Zenidd](https://github.com/Zenidd)) [PR#285](https://github.com/wazuh/wazuh-puppet/pull/285)

### Fixed

- ossec.conf concat resources rename ([@Zenidd](https://github.com/Zenidd)) [PR#293](https://github.com/wazuh/wazuh-puppet/pull/293)

- Adding syslog_output support on wazuh-puppet ([@Zenidd](https://github.com/Zenidd)) [PR#276](https://github.com/wazuh/wazuh-puppet/pull/276)


## Wazuh Puppet v3.13.1_7.8.0

### Added

- Update to Wazuh version 3.13.1_7.8.0


## Wazuh Puppet v3.13.0_7.7.1

### Added

- Update to Wazuh version 3.13.0_7.7.1
- Add syscollector related config in Wazuh Agent manifest ([@rshad](https://github.com/rshad)) [PR#241](https://github.com/wazuh/wazuh-puppet/pull/241)

## Wazuh Puppet v3.12.3_7.6.2

### Added

- Update to Wazuh version 3.12.3_7.6.2
- Add option for report files changes in syscheck ([@Hexta](https://github.com/Hexta)) [PR#212](https://github.com/wazuh/wazuh-puppet/pull/212)

## Wazuh Puppet v3.12.2_7.6.2

### Added

- Update to Wazuh version 3.12.2_7.6.2

## Wazuh Puppet v3.12.0_7.6.1

### Added

- Update to Wazuh version 3.12.0_7.6.1

- Add a parameter ossec_rootcheck_ignore_list ([@Hexta](https://github.com/Hexta)) [PR#212](https://github.com/wazuh/wazuh-puppet/pull/212)

- Add a parameter wazuh_api::manage_nodejs_package ([@Hexta](https://github.com/Hexta)) [PR#213](https://github.com/wazuh/wazuh-puppet/pull/213)

- Upgrade to NodeJS v10 ([@xr09](https://github.com/xr09)) [PR#230](https://github.com/wazuh/wazuh-puppet/pull/230)

- Always treat $ossec_emailnotification as a boolean ([@alanwevans](https://github.com/alanwevans)) [PR#229](https://github.com/wazuh/wazuh-puppet/pull/229)

- Adapt active-response definition ([@rshad](https://github.com/rshad)) [PR#234](https://github.com/wazuh/wazuh-puppet/pull/234)

### Fixed

- Fixes #215: Fix audit package name for Debian ([@djmgit](https://github.com/djmgit)) [PR#216](https://github.com/wazuh/wazuh-puppet/pull/216)

- Fixes #227 : Add system_audit subsection in rootcheck ([@djmgit](https://github.com/djmgit)) [PR#228](https://github.com/wazuh/wazuh-puppet/pull/228)

- Fixes #225 : Option to configure audit rules from this module itself ([@djmgit](https://github.com/djmgit)) [PR#226](https://github.com/wazuh/wazuh-puppet/pull/226)

- Fixes #221 : No kern.log, auth.log, mail.log in default localfile config for Debian family ([@rshad](https://github.com/rshad)) [Issue#221](https://github.com/wazuh/wazuh-puppet/issues/221)

## Wazuh Puppet v3.11.4_7.6.1

### Added

- Update to Wazuh version 3.11.4_7.6.1

## Wazuh Puppet v3.11.3_7.5.2

### Added

- Update to Wazuh version 3.11.3_7.5.2

- Improved agent Windows config. and secondary fixes ([@rshad](https://github.com/rshad)) [PR#205](https://github.com/wazuh/wazuh-puppet/pull/205)

## Wazuh Puppet v3.11.2_7.5.1

### Added

- Update to Wazuh version 3.11.2_7.5.1

### Fixed

- Fixed installation for Amazon Linux OS ([@rshad](https://github.com/rshad)) [PR#197](https://github.com/wazuh/wazuh-puppet/pull/197)

## Wazuh Puppet v3.11.1_7.5.1

### Added

- Update to Wazuh version 3.11.1_7.5.1

- Adapt to new Wazuh API configuration ([@jm404](https://github.com/jm404)) [PR#195](https://github.com/wazuh/wazuh-puppet/pull/195)

- Some templates have been parametrized ([@rshad](https://github.com/rshad)) [PR#187](https://github.com/wazuh/wazuh-puppet/pull/187)

### Changed

- Implemented Changes to make `ossec.conf` equivalent to the default version ([@rshad](https://github.com/rshad)) [PR#190](https://github.com/wazuh/wazuh-puppet/pull/190)

## Wazuh Puppet v3.11.0_7.5.1

### Added

- Update to Wazuh version 3.11.0_7.5.1

- Added Debian Buster support ([@aderumier](https://github.com/aderumier)) [PR#167](https://github.com/wazuh/wazuh-puppet/pull/167)

- Add OracleLinux to manager and agent ([@rwaffen](https://github.com/rwaffen)) [PR#153](https://github.com/wazuh/wazuh-puppet/pull/153)

### Fixed

- Fixed Windows Agent Installation ([@JPLachance](https://github.com/JPLachance)) [PR#163](https://github.com/wazuh/wazuh-puppet/pull/163)

## Wazuh Puppet v3.10.2_7.3.2

### Added

- Update to Wazuh version 3.10.2_7.3.2

## Wazuh Puppet v3.10.0_7.3.2

### Added

- Update to Wazuh version 3.10.0_7.3.2
- Change Wazuh Filebeat Module to production. ([@jm404](https://github.com/jm404)) [#1bc6b792af68ff26fc0dfc9125e5d33f7831b32e](https://github.com/wazuh/wazuh-puppet/commit/1bc6b792af68ff26fc0dfc9125e5d33f7831b32e)

## Fixed
- Fixes for Ossec email notifications' config ([rshad](https://github.com/rshad)) [PR#150](https://github.com/wazuh/wazuh-puppet/pull/150)

## Wazuh Puppet v3.9.5_7.2.1

### Added

- Update to Wazuh version 3.9.5_7.2.1

## Fixed

- Fixed linting problems ([@jm404](https://github.com/jm404)) [#ca923c7](https://github.com/wazuh/wazuh-puppet/commit/ca923c71a8f13c75d1f8a0a4807dda6f3ba114a6)



## Wazuh Puppet v3.9.4_7.2.0

### Added

- Update to Wazuh version 3.9.4_7.2.0

- Added Filebeat module and adapted Elasticsearch IP ([rshad](https://github.com/rshad)) [PR#144](https://github.com/wazuh/wazuh-puppet/pull/144)

- Added Kitchen testing for Wazuh deployment with Puppet. ([rshad](https://github.com/rshad)) [PR#139](https://github.com/wazuh/wazuh-puppet/pull/139)

- Added Ubuntu as a recognized operating system to Puppet manifests. ([rshad](https://github.com/rshad)) [PR#141](https://github.com/wazuh/wazuh-puppet/pull/141)

- Wazuh Agent is now able to register and report to different IPs. ([@jm404](https://github.com/jm404)) [PR#136](https://github.com/wazuh/wazuh-puppet/pull/136)

### Fixed

- Fixed integration when group is not specified. ([TheoPoc](https://github.com/TheoPoc)) [PR#142](https://github.com/wazuh/wazuh-puppet/pull/142)

### Changed

- Moved command and email_alert templates to templates/fragments. ([rshad](https://github.com/rshad)) [PR#143](https://github.com/wazuh/wazuh-puppet/pull/143)


## Wazuh Puppet v3.9.3_7.2.0

### Added

- Update to Wazuh version 3.9.3_7.2.0

## Wazuh Puppet v3.9.2_7.1.1

### Added

- Update to Wazuh version 3.9.2_7.1.1

## Wazuh Puppet v3.9.1_7.1.0

### Added

- Created required files for Filebeat installation. ([@jm404](https://github.com/jm404)) [#f36be695](https://github.com/wazuh/wazuh-puppet/commit/f36be69558f012a75717150bd6a48f9b9a45b3c8)

- Created required files for Elasticsearch installation. ([@jm404](https://github.com/jm404)) [#890fb88](https://github.com/wazuh/wazuh-puppet/commit/890fb88cdb4f18ea67caaf09943792145ac245bd)

- Created required files for Kibana installation. ([@jm404](https://github.com/jm404)) [#ac31a02](https://github.com/wazuh/wazuh-puppet/commit/ac31a02c5a6771e5e480db378934b23e2dc59b03)

- Added configuration variables to make `ossec.conf` more flexible. ([@jm404](https://github.com/jm404)) [#5631753](https://github.com/wazuh/wazuh-puppet/commit/5631753cf4c3967d7fc08fc53d2535d78d4e19b7)

- Now it's possible to install an agent without registering it. ([@jm404](https://github.com/jm404)) [#63e1a13](https://github.com/wazuh/wazuh-puppet/commit/63e1a1390edbaef4387c4397c16636514525eeaa)
- Added support for Amazon-Linux-2. ([@jm404](https://github.com/jm404)) [#823eeec](https://github.com/wazuh/wazuh-puppet/commit/823eeec502c4a100dc6946f25388b9d04833c105)

### Changed

- The `server.pp` manifest has been renamed to `manager.pp`. ([@jm404](https://github.com/jm404)) [#f859f87](https://github.com/wazuh/wazuh-puppet/commit/f859f879e5bd6e83b4adf54ebbe44adfc60c0f03)
- The `client.pp` manifest moved to `agent.pp`. ([@jm404](https://github.com/jm404)) [#69fe628](https://github.com/wazuh/wazuh-puppet/commit/69fe628bfbfec171fce3754b22f1d04b67d58d81)

## Removed

- Registration method `export` deleted due to security issues. ([@jm404](https://github.com/jm404)) [#f77fe49](https://github.com/wazuh/wazuh-puppet/commit/f77fe496b4e290b0b3a70272c66d26f8ee7d0012)
- Eliminated `inotify-tools `. ([@jm404](https://github.com/jm404)) [#628db1e](https://github.com/wazuh/wazuh-puppet/commit/628db1e4d5236b195ee1c50945fb6ff7553a5b23)
- Deleted `_common.erb` fragment in order to give flexibility to Agent and Manager. ([@jm404](https://github.com/jm404)) [#92114ea](https://github.com/wazuh/wazuh-puppet/commit/92114ea205be4fa6783115b01b1148a2a6dc7c2d)


## [v3.9.1]

### Added

- Update to Wazuh version 3.9.1_6.8.0

## [v3.9.0]

### Added

- Allow certificates to be defined by file path ([#112](https://github.com/wazuh/wazuh-puppet/pull/112))

### Changed

- Update to Wazuh version 3.9.0 ([#118](https://github.com/wazuh/wazuh-puppet/pull/118))

## [v3.8.2]

### Changed

- Update to Wazuh version 3.8.2. ([#107](https://github.com/wazuh/wazuh-puppet/pull/107))

## [v3.8.1]

### Changed
- Update to Wazuh version 3.8.1 ([#104](https://github.com/wazuh/wazuh-puppet/pull/104))

## [v3.8.0]

### Added
- Feature/agent auth cert key ([#98](https://github.com/wazuh/wazuh-puppet/pull/98))
- Install package even if repos are not managed by wazuh ([#99](https://github.com/wazuh/wazuh-puppet/pull/99))

### Added
- Updating params.pp and _common.erb so all the options of localfile can be used ([#97](https://github.com/wazuh/wazuh-puppet/pull/97))

## [v3.7.2]

### Added
- Updating params.pp and _common.erb so all the options of localfile can be used ([#97](https://github.com/wazuh/wazuh-puppet/pull/97))

### Fixed

- Fixing process_list.erb performance ([#94](https://github.com/wazuh/wazuh-puppet/pull/94))
- Update windows agent version ([#96](https://github.com/wazuh/wazuh-puppet/pull/96))

## [v3.7.1]

### Added

- Add integration support. ([#89](https://github.com/wazuh/wazuh-puppet/pull/89))
- Add support for who data. ([#84](https://github.com/wazuh/wazuh-puppet/pull/84))
- Grouping agents. ([#82](https://github.com/wazuh/wazuh-puppet/pull/82))

### Fixed

- Fix firewall module and support excluding decoders and rules. ([#81](https://github.com/wazuh/wazuh-puppet/pull/81))

### Changed

- Updated metadata.json.
- Changed addlog for command support. ([#90](https://github.com/wazuh/wazuh-puppet/pull/90))

## v3.7.0-3701

### Added

- New repository management and content.
- Add support for Wazuh 3.x. ([#85](https://github.com/wazuh/wazuh-puppet/pull/85))

### Fixed

- Fix username (puppet to puppetlabs). ([#74](https://github.com/wazuh/wazuh-puppet/pull/74))

## Change Log old version.


 ## 2017-xx-xx support@wazuh.com  - 2.0.23

  * Fixed issue #18 with the pull request #17. (thanks @lemrouch)
  * Fixed issue #29 puppetlabs/apt version 4 onwards breaks the installation of wazuh server (thanks @rafaelfc-olx)
  * Adding support for changing ossec_server_protocol with the pull request #30 (thanks @rafaelfc-olx)
  * Managing wazuh-api alongside with wazuh-manager with the pull request #31 (thanks @rafaelfc-olx)
  * Preventing Duplicated declaration issues regarding apt-transport-https package with the pull request #32 (thanks @rafaelfc-olx)
  * Adding support for changing the client protocol and validating the manager by CA with the pull request #34 (thanks @rafaelfc-olx)
  * Configuring wazuh-api from puppet with the pull request #35 (thanks @rafaelfc-olx)
  * Adding notify_time and time-reconnect options to client config with the pull request #36 (thanks @rafaelfc-olx)
  * New wazuh-winagent-v2.1.1-1.exe added.
  * Profile name for Centos 7 is not _server, it's _common like RHEL7 with the pull request #38 (thanks @juliovalcarcel)
  * Verifying if @wodle_openscap_content is defined, fixed #45 and #46
  * Set the same file permissions than the installed package, fixed #41
  * Adding the ability to set "type" attribute for "ignore" tag, fixed #19
  * Adding support to OracleLinux, Fixed #43
  * Add an option for the agent/manager class to manage the firewall automatically with puppetlabs/firewall

## 2017-05-27 support@wazuh.com  - 2.0.22


  * Fixed issue #3. (Thanks for reporting it @ddholstad99)
  * Fixed issue #4. (Thanks for reporting it @elisiano)
  * Explicitly use the windows package provider pull request #11 (Thanks @damoxc)
  * Enable fedora 23/24/25 for pull request #9 (Thanks @ddholstad99)
  * Fix for issue Fix for #6 validate_cmd pull request #12 (Thanks @dakine1111)
  * Add $wodle_openscap_content parameter to server.pp pull request #12 (Thanks hex2a)
  * Added some changes in order to do this module compatible. (pull request #5 thanks elisano)

## 2017-04-24 Jose Luis Ruiz  - 2.0.21

  * Fix apt deprecation warnings. (thanks @kdole)
  * Avoid warnings when storeconfigs are not available. (thanks @kdole)
  * Use default local_files setting. (thanks @kdole)
  * Making ossec server port configurable. (thanks @edge-records)
  * Allow custom agent configurations (thanks @ffleming)
  * Fixed issec #66 (thanks @thedawidbalut)
  * Adds options to control rootcheck feature. (thanks @netman2k)
  * Use puppet-selinux instead of jfryman-selinux (thanks @netman2k)
  * Allow custom ossec.conf in agent and server template (thanks @sam-wouters)
  * Fixed issue #71. (Thanks for reporting it @sc-chad)
  * Fixed issue #72. (Thanks for reporting it @sc-chad)
  * Clean code and added new OpenScap option (thanks @0x2A)
  * module refactored/adapted for wazuh 2.0 (thanks @0x2A)
  * New wazuh-agent-2.0.exe for Windows.

## 2016-12-08 Jose Luis Ruiz  - 2.0.20


  * Fixed typo in the windows package, this type made the deploy fails under windows.

## 2016-12-08 Jose Luis Ruiz  - 2.0.19

  * Compat with Older versions facter. (pull request #47 thanks @seefood)
  * Template paths as parameters. (pull request #48 thanks @seefood )
  * Client: allow configurable service_has_status, default to params. (pull request #51 thanks @josephholsten )
  * Added Yakketi to the supported distributions.
  * Modified activeresponse.erb to include <rules_id></rules_id> tags (pull request #56 thanks @MatthewRBruce)
  * Modified client.pp and server.pp to accept package versions as parameter. (pull request #57 thanks @MatthewRBruce)

## 2016-10-20 Jose Luis Ruiz  - 2.0.18


  * Fixed 10_ossec.conf.erb template, "local_decoder" added to rules configuration

## 2016-10-18 Jose Luis Ruiz  - 2.0.17

  * Fixed gpgkey path under CentOS and RHEL

## 2016-10-18 Jose Luis Ruiz  - 2.0.16

  * Add local_decoder.xml and local_rules.xml templates


## 2016-10-15 Jose Luis Ruiz  - 2.0.15

  * Add option to enable syslog output. (pull request #35 thanks @TravellingGUy )
  * Add Add Amazon Linux support. (pull request #37 thanks @seefood)
  * Hard-coded GPG key for RHEL-like systems. (pull request #37 thanks @tobowers)
  * Override package & service name for client installation. (pull request #43 thanks MrSecure)

## 2016-06-14 Jose Luis Ruiz  - 2.0.14

  * Add prefilter to agent config. (pull request #32 thanks @cmblong )
  * Add function addlog to the agent. (issue #30 thanks @paul-cs)
  * Add the apt::key can set a proxy and the key add process could be done. (issue #34 thanks @drequena)

## 2016-06-14 Jose Luis Ruiz  - 2.0.13

  * Adding xenial to the supported distributions.(pull request #31 thanks @stephen-kainos)

## 2016-05-04 Jose Luis Ruiz  - 2.0.12

Jose Luis Ruiz <jose@wazuh.com>:

  * Add MariaDB support ( (pull reques #3 thanks @ialokin)
  * Permit admin to disable auto_ignore for files which change more than three times. (pull request #24 thanks @cmblong)
  * Change fqdn_rand(3000) to a variable to allow us to increase the number of available clients. (pull request #25 thanks @cmblong)
  * Can now set a minimal activeresponse entry containing just repeated_offenders by defining $ar_repeated_offenders in the wazuh::client. (pull request #26 thanks @ialokin)
  * Add variable to enable prefilter command.  (pull request #27 thanks @cmblong)
  * Set service provider to redhat on Redhat systems. (pull request #28 thanks @cmblong))

## 2016-05-04 Jose Luis Ruiz  - 2.0.11

Jose Luis Ruiz <jose@wazuh.com>:

  * Fix windows installation error in params. (pull request #20 thanks @cmblong)
  * Added support for repeated_offenders in activeresponse (pull request #21 thanks @ialokin)

## 2016-04-26 Jose Luis Ruiz  - 2.0.10

Jose Luis Ruiz <jose@wazuh.com>:

  * Extra rules config to integrate Wazuh ruleset. (pull request #17 thanks @TravellingGUy)
  * Allow configuration of the email_maxperhour and email_idsname configuration items. (pull request #18 thanks @TravellingGUy)
  * Fix bug in client exported resources (pull request #19 thanks @scottcunningham)

## 2016-02-23 Jose Luis Ruiz  - 2.0.9

Jose Luis Ruiz <jose@wazuh.com>:

  * Allow the agent identity to be modified. (pull request #10 thanks @damoxc)
  * prevent the agent-auth command being used. (pull request #11 thanks @damoxc)
  * Change log directory to only be readable by user and group. (pull request #12 thanks @damoxc)
  * Add the ability to configure a MySQL database with OSSEC server. (pull request #14 thanks @coreone)

## 2016-02-05 Jose Luis Ruiz  - 2.0.8

Jose Luis Ruiz <jose@wazuh.com>:

  * Fix some typos with puppet-lint.

## 2016-02-05 Jose Luis Ruiz <jose@wazuh.com> - 2.0.7

Jose Luis Ruiz <jose@wazuh.com>:

  * Run agent-auth if client.keys doesn't exist an agent. (pull request #9 thanks @TravellingGuy)

## 2016-02-03 Jose Luis Ruiz <jose@wazuh.com> - 2.0.6

Jose Luis Ruiz <jose@wazuh.com>:

  * Add ability to manage epel repo to master/client configs (pull request #4 thanks @justicel)
  * The @path uses the puppet level path variable (pull request #5 thanks @justicel)
  * Allow whitelisting of IP addreses (thanks @chaordix)
  * Provides an option to tell the puppet module to not manage the client.keys file at all. (pull request #7 thanks @TravellingGuy)

## 2016-01-19 Jose Luis Ruiz <jose@wazuh.com> - 2.0.5

Jose Luis Ruiz <jose@wazuh.com>:

  * Add multiple email_to addresses
  * Adding support for server-hostname in agent config (pull request #3 thanks @alustenberg)
  * Adding ossec_scanpaths configuration thanks to @djjudas21 repository

## 2015-12-21 Jose Luis Ruiz <jose@wazuh.com> - 2.0.4

Jose Luis Ruiz <jose@wazuh.com>:

  * Add manage_repo option on client.pp (issue #2 reported by @cudgel)
  * Add new repo for RHEL5 and CentOS5 have different rpm signature.

## 2015-12-02 Jose Luis Ruiz <jose@wazuh.com> - 2.0.3

Jose Luis Ruiz <jose@wazuh.com>:

  * Fix server package name for Ubuntu (thanks to @HielkeJ for Pull request)
  * Add full fingerprint for Ubuntu and Debian (thanks to @HielkeJ for Pull request)

## 2015-10-13 Jose Luis Ruiz <jose@wazuh.com> - 2.0.2

Jose Luis Ruiz <jose@wazuh.com>:

  * Update Windows Agent to version 2.8.3
  * Update packaget to Ubuntu Vivid and Wily
  * Update packages to Debian Stretch and Sid

## 2015-10-13 Jose Luis Ruiz <jose@wazuh.com> - 2.0.1

Jose Luis Ruiz <jose@wazuh.com>:

  * Update Windows Agent to version 2.8.1
  * Fix a bug with the Windows Agent ID, now use for all systems **fqdn_rand** to generate the client.keys ID

## 2015-09-16 Jose Luis Ruiz <jose@wazuh.com> - 2.0.0

Jose Luis Ruiz <jose@wazuh.com>:

  * Update for all kind of Windows
  * Change repos to Wazuh, Inc.

## 2015-09-16 Michael Porter <michael.porter@lightningsource.com> - 2.0.0

Michael Porter <michael.porter@lightningsource.com>:
  * Allow skipping MySQL dependency, disabling active response,
    and executing rootcheck
  * Windows agent support
  * Use Puppet md5 support, instead of adding parser function
  * Utilize centralized agent configuration
  * Various clean-up and reorganization of Puppet module structure
  * Utilize 'hostname' instead of 'uniqueid' for agent ID, due to uniqueid
    not existing on Windows, and not necessarily being unique across the org
    on Linux

##  2015-08-21 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.7.2

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * SELinux permissions fix

## 2015-08-07 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.7.0

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Use puppetlabs/mysql to manage MySQL client

## 2015-08-03 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.6.2

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Fix log directory permissions

## 2015-07-20 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.6.0

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Enable SELinux support

## 2015-07-06 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.5.4

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Fix regression in log file permissions (thanks to @paulseward)

## 2015-06-30 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.5.3

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Fix permissions on log files so logwatch on EL7 doesn't complain
  * Key concat::fragment for agentkeys on $agent_name to avoid duplicated resources

## 2015-06-11 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.5.1

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Stop using andyshinn/atomic and configure Atomicorp's OSSEC repo locally

## 2015-06-10 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.4.2

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Fix regression that breaks behaviour on CentOS 6 and lower

## 2015-05-28 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.4.1

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Email notification is no longer hard-coded in ossec.conf (thanks to @earsdown)

## 2015-03-02 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.4.0

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Fix dependency problem by providing EPEL on RHEL (thanks to @otteydw for reporting)

## 2015-01-16 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.3.3

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Fix compatibility issue with PuppetServer (thanks to @d9705996)

## 2014-11-28 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk> - 1.3.0

 Jonathan Gazeley <jonathan.gazeley@bristol.ac.uk>:
  * Add support for Debian "Jessie" (thanks to @ivan7farre)
