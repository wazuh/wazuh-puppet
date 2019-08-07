# Wazuh Puppet module

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

This module installs and configure Wazuh agent and manager.

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [Wazuh Puppet module documentation](https://documentation.wazuh.com/current/deploying-with-puppet/index.html)
* [Puppet Forge](https://forge.puppetlabs.com/wazuh/wazuh)

## Directory structure

    wazuh-puppet/
    ├── CHANGELOG.md
    ├── checksums.json
    ├── files
    │   └── ossec-logrotate.te
    ├── Gemfile
    ├── LICENSE.txt
    ├── manifests
    │   ├── activeresponse.pp
    │   ├── addlog.pp
    │   ├── agent.pp
    │   ├── command.pp
    │   ├── elasticsearch.pp
    │   ├── email_alert.pp
    │   ├── filebeat.pp
    │   ├── init.pp
    │   ├── integration.pp
    │   ├── kibana.pp
    │   ├── manager.pp
    │   ├── params_agent.pp
    │   ├── params_elastic.pp
    │   ├── params_manager.pp
    │   ├── repo_elastic.pp
    │   ├── repo.pp
    │   ├── reports.pp
    │   └── wazuh_api.pp
    ├── metadata.json
    ├── Rakefile
    ├── README.md
    ├── spec
    │   ├── classes
    │   │   ├── client_spec.rb
    │   │   ├── init_spec.rb
    │   │   └── server_spec.rb
    │   └── spec_helper.rb
    ├── templates
    │   ├── api
    │   │   └── config.js.erb
    │   ├── default_commands.erb
    │   ├── elasticsearch_yml.erb
    │   ├── filebeat_yml.erb
    │   ├── fragments
    │   │   ├── _activeresponse.erb
    │   │   ├── _auth.erb
    │   │   ├── _cluster.erb
    │   │   ├── _command.erb
    │   │   ├── _default_activeresponse.erb
    │   │   ├── _email_alert.erb
    │   │   ├── _integration.erb
    │   │   ├── _localfile.erb
    │   │   ├── _localfile_generation.erb
    │   │   ├── _reports.erb
    │   │   ├── _rootcheck.erb
    │   │   ├── _ruleset.erb
    │   │   ├── _sca.erb
    │   │   ├── _syscheck.erb
    │   │   ├── _wodle_cis_cat.erb
    │   │   ├── _wodle_openscap.erb
    │   │   ├── _wodle_osquery.erb
    │   │   ├── _wodle_syscollector.erb
    │   │   └── _wodle_vulnerability_detector.erb
    │   ├── jvm_options.erb
    │   ├── kibana_yml.erb
    │   ├── local_decoder.xml.erb
    │   ├── local_rules.xml.erb
    │   ├── ossec_shared_agent.conf.erb
    │   ├── process_list.erb
    │   ├── wazuh_agent.conf.erb
    │   └── wazuh_manager.conf.erb
    ├── tests
    │   └── init.pp
    └── VERSION

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
Copyright (C) 2019 Wazuh Inc.  (License GPLv2)

Based on OSSEC
Copyright (C) 2015 Trend Micro Inc.


## Web References

* [Wazuh website](http://wazuh.com)
