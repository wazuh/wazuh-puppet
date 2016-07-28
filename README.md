# Wauh Puppet module

This module installs and configure Wazuh agent and manager.

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [OSSEC Puppet module documentation](http://documentation.wazuh.com/en/latest/ossec_puppet.html#ossec-puppet-module)
* [Puppet Forge](https://forge.puppetlabs.com/wazuh/ossec)

## Credits and thank you

This Puppet module has been authored by Nicolas Zin, and updated by Jonathan Gazeley and Michael Porter. Wazuh has forked it with the purpose of maintaing it. Thank you to the authors for the contribution.

## References

* [Wazuh website](http://wazuh.com)
* [OSSEC project website](http://ossec.github.io)

## Wazuh Manager manfiest example

```
node "manager.xxxx.com" {
   class { 'wazuh::server':
     mailserver_ip => 'localhost',
     ossec_emailto => ['ossec@xxxx.com']
   }

   wazuh::addlog { 'monitorLogFile':
     logfile => '/var/log/secure',
     logtype => 'syslog'
   }

   wazuh::addlog {
     'monitorLogFile2':
       logfile => '/var/log/secure2',
       logtype => 'syslog'
   }
}
```
## Wazuh Agent manifest example

```
node "agent.xxx.com" {
class { "wazuh::client":
  ossec_server_ip => "192.168.145.145"
}

   wazuh::addlog {
     'monitorLogFile2':
       agent_log => true,
       logfile => '/var/log/secure2',
       logtype => 'syslog'
   }

   wazuh::addlog {
     'monitorLogFile3':
       agent_log => true,
       logfile => '/var/log/secure3',
       logtype => 'syslog'
   }

}
```
