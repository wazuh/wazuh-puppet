# Wazuh Puppet module

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://goo.gl/forms/M2AoZC4b2R9A9Zy12)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

This module installs and configure Wazuh agent and manager.

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [Wazuh Puppet module documentation](https://documentation.wazuh.com/current/deploying-with-puppet/index.html)
* [Puppet Forge](https://forge.puppetlabs.com/wazuh/wazuh)

## Directory structure

    ├── wazuh-puppet
    │ ├── files           
    │ │ ├── client.keys
    │ │ ├── ossec-logrotate.te
    │ │ ├── wazuh-winagent-v2.1.1-1.exe
    │
    │ ├── manifest
    │ │ ├── activeresponse.pp
    │ │ ├── addlog.pp
    │ │ ├── agentkey.pp
    │ │ ├── client.pp
    │ │ ├── collect_agent_keys.pp
    │ │ ├── command.pp
    │ │ ├── email_alert.pp
    │ │ ├── export_agent_key.pp
    │ │ ├── init.pp
    │ │ ├── params.pp
    │ │ ├── repo.pp
    │ │ ├── reports.pp
    │ │ ├── server.pp
    │ │ 
    │ ├── spec
    │ │ ├── classes
    │ │ │ ├── client_spec.rb
    │ │ │ ├── init_spec.rb
    │ │ │ ├── server_spec.rb
    │ │ 
    │ │ ├── spec_helper.rb
    │
    │ ├── templates
    │ │ ├── api
    │ │ │ ├── config.js.erb
    │ │ 
    │ │ ├── fragments
    │ │ │ ├── _activeresponse.erb
    │ │ │ ├── _common.erb
    │ │ │ ├── _localfile.erb
    │ │ │ ├── _reports.erb
    │ │ │ ├── _rootcheck_linux.erb
    │ │ │ ├── _rootcheck_windows.erb
    │ │ │ ├── _syscheck_linux.erb
    │ │ │ ├── _syscheck_windows.erb
    │ │ │ ├── _wodle_openscap.erb 
    │ │
    │ │ ├── command.erb
    │ │ ├── email_alert.erb
    │ │ ├── local_decoder.xml.erb
    │ │ ├── local_rules.xmk.erb
    │ │ ├── ossec_shared_agent.conf.erb
    │ │ ├── process_list.erb
    │ │ ├── wazuh_agent.conf.erb
    │ │ ├── wazuh_manager.conf.erb
    |
    │ ├── tests
    │ │ ├── init.pp 
    | 
    │ ├── README.md
    │ ├── VERSION
    │ ├── CHANGELOG.md
    │ ├── .travis.yml
    │ ├── Gemfile
    │ ├── LICENSE.txt
    │ ├── Rakefile
    │ ├── checksums.json
    │ ├── metadata.json

## Branches

* `stable` branch on correspond to the last Wazuh-Puppet stable version.
* `master` branch contains the latest code, be aware of possible bugs on this branch.

## Contribute

If you would like to contribute to our repository, please fork our Github repository and submit a pull request.

If you are not familiar with Github, you can also share them through [our users mailing list](https://groups.google.com/d/forum/wazuh), to which you can subscribe by sending an email to `wazuh+subscribe@googlegroups.com`. 


## Credits and thank you

This Puppet module has been authored by Nicolas Zin, and updated by Jonathan Gazeley and Michael Porter. Wazuh has forked it with the purpose of maintaining it. Thank you to the authors for the contribution.

## License and copyright

WAZUH
Copyright (C) 2016-2018 Wazuh Inc.  (License GPLv2)

Based on OSSEC
Copyright (C) 2015 Trend Micro Inc.


## Web References

* [Wazuh website](http://wazuh.com)
