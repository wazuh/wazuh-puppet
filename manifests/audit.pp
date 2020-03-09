class wazuh::audit (
  $audit_manage_rules = false,
  $audit_buffer_bytes = "8192",
  $audit_backlog_wait_time = "0",
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

        file { 'Configure audit.rules':
          owner   => 'root',
          group   => 'root',
          path    => '/etc/audit/rules.d/audit.rules',
          mode    => '0644',
          notify  => Service['auditd'], ## Restarts the service
          content => template('wazuh/audit_rules.erb')
        }
      }
    }
  }
}
