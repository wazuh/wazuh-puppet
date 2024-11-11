# Wazuh Puppet module

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Web](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
![Kitchen tests for Wazuh Puppet](https://github.com/wazuh/wazuh-puppet/workflows/Kitchen%20tests%20for%20Wazuh%20Puppet/badge.svg)

This module installs and configure Wazuh agent and manager.

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [Wazuh Puppet module documentation](https://documentation.wazuh.com/current/deploying-with-puppet/index.html)
* [Puppet Forge](https://forge.puppetlabs.com/wazuh/wazuh)

## Directory structure

    wazuh-puppet/
    ├── CHANGELOG.md
    ├── checksums.json
    ├── data
    │   └── common.yaml
    ├── files
    │   └── ossec-logrotate.te
    ├── Gemfile
    ├── kitchen
    │   ├── chefignore
    │   ├── clean.sh
    │   ├── Gemfile
    │   ├── hieradata
    │   │   ├── common.yaml
    │   │   └── roles
    │   │       └── default.yaml
    │   ├── kitchen.yml
    │   ├── manifests
    │   │   └── site.pp.template
    │   ├── Puppetfile
    │   ├── README.md
    │   ├── run.sh
    │   └── test
    │       └── integration
    │           ├── agent
    │           │   └── agent_spec.rb
    │           └── mngr
    │               └── manager_spec.rb
    ├── LICENSE.txt
    ├── manifests
    │   ├── activeresponse.pp
    │   ├── addlog.pp
    │   ├── agent.pp
    │   ├── audit.pp
    │   ├── certificates.pp
    │   ├── command.pp
    │   ├── dashboard.pp
    │   ├── email_alert.pp
    │   ├── filebeat_oss.pp
    │   ├── indexer.pp
    │   ├── init.pp
    │   ├── integration.pp
    │   ├── manager.pp
    │   ├── params_agent.pp
    │   ├── params_manager.pp
    │   ├── repo_elastic_oss.pp
    │   ├── repo.pp
    │   ├── reports.pp
    │   └── tests.pp
    ├── metadata.json
    ├── Rakefile
    ├── README.md
    ├── spec
    │   ├── classes
    │   │   ├── client_spec.rb
    │   │   ├── init_spec.rb
    │   │   └── server_spec.rb
    │   └── spec_helper.rb
    ├── templates
    │   ├── default_commands.erb
    │   ├── filebeat_oss_yml.erb
    │   ├── fragments
    │   │   ├── _activeresponse.erb
    │   │   ├── _auth.erb
    │   │   ├── _cluster.erb
    │   │   ├── _command.erb
    │   │   ├── _default_activeresponse.erb
    │   │   ├── _email_alert.erb
    │   │   ├── _integration.epp
    │   │   ├── _labels.erb
    │   │   ├── _localfile.erb
    │   │   ├── _localfile_generation.erb
    │   │   ├── _reports.erb
    │   │   ├── _rootcheck.erb
    │   │   ├── _ruleset.erb
    │   │   ├── _sca.erb
    │   │   ├── _syscheck.erb
    │   │   ├── _syslog_output.erb
    │   │   ├── _vulnerability_detection.erb
    │   │   ├── _vulnerability_indexer.erb
    │   │   ├── _wodle_cis_cat.erb
    │   │   ├── _wodle_openscap.erb
    │   │   ├── _wodle_osquery.erb
    │   │   └── _wodle_syscollector.erb
    │   ├── disabledlog4j_options.erb
    │   ├── local_decoder.xml.erb
    │   ├── local_rules.xml.erb
    │   ├── ossec_shared_agent.conf.erb
    │   ├── process_list.erb
    │   ├── wazuh_agent.conf.erb
    │   ├── wazuh_api_yml.erb
    │   ├── wazuh_config_yml.erb
    │   ├── wazuh_manager.conf.erb
    │   └── wazuh_yml.erb
    └── VERSION

## Branches

* `master` branch contains the latest code, be aware of possible bugs on this branch.
* `stable` branch on correspond to the last Wazuh-Puppet stable version.

## Wazuh Integrations

Wazuh integrations might be used and declared by using a few hiera variables.

* `wazuh::manager::configure_integration`: Boolean, true or false. If true, looks for integration and use them. If false, ignore any declaration of integration.
* `wazuh::manager::ossec_integration`: Hash, containing declarations of miscellaneous integrations.

### Structure and variables of the `wazuh::manager::ossec_integration` hash:

* `hook_url`
* `api_key`
* `rule_id`
* `level`
* `group`
* `event_location`
* `alert_format`
* `max_log`

All those variables are explained on the Wazuh site:
https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html


### Integration example

This will create two integrations, one to slack, and one to mattermost:

```yaml
---
wazuh::manager::configure_integration: true
wazuh::manager::ossec_integration:
  'slack':
    alert_format: 'json'
    hook_url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
    level: '12'
  'mattermost':
    alert_format: 'json'
    hook_url: 'https://mattermost.domain.tld/hooks/XXXXXXXXXXXXXXXXXXXXXXXX'
    level: '12'
```

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) or the [Wazuh Slack community channel](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## Credits and thank you

This Puppet module has been authored by Nicolas Zin, and updated by Jonathan Gazeley and Michael Porter. Wazuh has forked it with the purpose of maintaining it. Thank you to the authors for the contribution.

## License and copyright

WAZUH
Copyright (C) 2015, Wazuh Inc.  (License GPLv2)

## Web References

* [Wazuh website](http://wazuh.com)
