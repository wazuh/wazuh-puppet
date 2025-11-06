# Copyright (C) 2015, Wazuh Inc.
# Define an ossec command
class wazuh::audit (
  $audit_manage_rules = false,
  $audit_buffer_bytes = '8192',
  $audit_backlog_wait_time = '0',
  $audit_rules = [],
  $audit_package_title = 'Installing Audit..',
) {
  case $facts['kernel'] {
    'Linux': {
      case $facts['os']['name'] {
        'Debian', 'debian', 'Ubuntu', 'ubuntu': {
          package { $audit_package_title:
            name => 'auditd',
          }
        }
        default: {
          package { $audit_package_title:
            name => 'audit',
          }
        }
      }

      service { 'auditd':
        ensure  => running,
        enable  => true,
        require => Package[$audit_package_title],
      }

      if $audit_manage_rules == true {
        file { '/etc/audit/rules.d/audit.rules':
          ensure  => file,
          require => Service['auditd'],
        }

        $audit_rules.each |String $rule| {
          file_line { "Append rule ${rule} to /etc/audit/rules.d/audit.rules":
            path    => '/etc/audit/rules.d/audit.rules',
            line    => $rule,
            require => File['/etc/audit/rules.d/audit.rules'],
          }
        }
      }
    }
    default: {
      fail("Module Audit not supported on ${facts['os']['name']}")
    }
  }
}
