# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Define an ossec command

class wazuh::audit (
  $audit_manage_rules = false,
  $audit_buffer_bytes = '8192',
  $audit_backlog_wait_time = '0',
  $audit_rules = [],
) {

  case $::kernel {
    'Linux': {
      case $::operatingsystem {
        'Debian', 'debian', 'Ubuntu', 'ubuntu': {
          package { 'Installing Audit...':
            name => 'auditd',
          }
        }
        default: {
          package { 'Installing Audit...':
            name => 'audit'
          }
        }
      }

      service { 'auditd':
        ensure => running,
        enable => true,
      }

      if $audit_manage_rules == true {
        file { '/etc/audit/rules.d/audit.rules':
          ensure => present
        }

        $audit_rules.each |String $rule| {
          file_line { "Append rule ${rule} to /etc/audit/rules.d/audit.rules":
            path    => '/etc/audit/rules.d/audit.rules',
            line    => $rule,
            require => File['/etc/audit/rules.d/audit.rules']
          }
        }
      }
    }
    default: {
      fail("Module Audit not supported on ${::operatingsystem}")
    }
  }
}
