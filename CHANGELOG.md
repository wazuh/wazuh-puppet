# Change Log
All notable changes to this project will be documented in this file.

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
