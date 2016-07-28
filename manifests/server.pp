# Main Wazuh manager config
class wazuh::server (
  $mailserver_ip,
  $ossec_emailto,
  $ossec_emailfrom                     = "wazuh@${::domain}",
  $ossec_active_response               = true,
  $ossec_rootcheck                     = true,
  $ossec_global_host_information_level = 8,
  $ossec_global_stat_level             = 8,
  $ossec_email_alert_level             = 7,
  $ossec_ignorepaths                   = [],
  $ossec_scanpaths                     = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'yes', 'realtime' => 'yes'} ],
  $ossec_white_list                    = [],
  $ossec_extra_rules_config            = [],
  $ossec_local_files                   = {},
  $ossec_emailnotification             = 'yes',
  $ossec_email_maxperhour              = '12',
  $ossec_email_idsname                 = undef,
  $ossec_check_frequency               = 79200,
  $ossec_auto_ignore                   = 'yes',
  $ossec_prefilter                     = false,
  $ossec_service_provider              = $::wazuh::params::ossec_service_provider,
  $use_mysql                           = false,
  $mariadb                             = false,
  $mysql_hostname                      = undef,
  $mysql_name                          = undef,
  $mysql_password                      = undef,
  $mysql_username                      = undef,
  $manage_repos                        = true,
  $manage_epel_repo                    = true,
  $manage_client_keys                  = true,
) inherits wazuh::params {
  validate_bool(
    $ossec_active_response, $ossec_rootcheck,
    $use_mysql, $manage_repos, $manage_epel_repo
  )
  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  #validate_integer($ossec_check_frequency, undef, 1800)
  validate_array($ossec_ignorepaths)

  if $::osfamily == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  if $manage_repos {
    # TODO: Allow filtering of EPEL requirement
    class { 'wazuh::repo': redhat_manage_epel => $manage_epel_repo }
    Class['wazuh::repo'] -> Package[$wazuh::params::server_package]
  }

  if $use_mysql {
    # Relies on mysql module specified in metadata.json
    if $mariadb {
      # if mariadb is true, then force the usage of the mariadb-client package
      class { 'mysql::client': package_name => 'mariadb-client' }
    } else {
      include mysql::client
    }
    Class['mysql::client'] ~> Service[$wazuh::params::server_service]
  }

  # install package
  package { $wazuh::params::server_package:
    ensure  => installed
  }

  service { $wazuh::params::server_service:
    ensure    => running,
    enable    => true,
    hasstatus => $wazuh::params::service_has_status,
    pattern   => $wazuh::params::server_service,
    provider  => $ossec_service_provider,
    require   => Package[$wazuh::params::server_package],
  }

  # configure ossec process list
  concat { $wazuh::params::processlist_file:
    owner   => $wazuh::params::config_owner,
    group   => $wazuh::params::config_group,
    mode    => $wazuh::params::config_mode,
    require => Package[$wazuh::params::server_package],
    notify  => Service[$wazuh::params::server_service]
  }
  concat::fragment { 'ossec_process_list_10' :
    target  => $wazuh::params::processlist_file,
    content => template('wazuh/10_process_list.erb'),
    order   => 10,
    notify  => Service[$wazuh::params::server_service]
  }

  # configure ossec
  concat { $wazuh::params::config_file:
    owner   => $wazuh::params::config_owner,
    group   => $wazuh::params::config_group,
    mode    => $wazuh::params::config_mode,
    require => Package[$wazuh::params::server_package],
    notify  => Service[$wazuh::params::server_service]
  }
  concat::fragment { 'ossec.conf_10' :
    target  => $wazuh::params::config_file,
    content => template('wazuh/10_ossec.conf.erb'),
    order   => 10,
    notify  => Service[$wazuh::params::server_service]
  }

  if $use_mysql {
    validate_string($mysql_hostname)
    validate_string($mysql_name)
    validate_string($mysql_password)
    validate_string($mysql_username)

    # Enable the database in the config
    concat::fragment { 'ossec.conf_80' :
      target  => $wazuh::params::config_file,
      content => template('wazuh/80_ossec.conf.erb'),
      order   => 80,
      notify  => Service[$wazuh::params::server_service]
    }

    # Enable the database daemon in the .process_list
    concat::fragment { 'ossec_process_list_20' :
      target  => $wazuh::params::processlist_file,
      content => template('wazuh/20_process_list.erb'),
      order   => 20,
      notify  => Service[$wazuh::params::server_service]
    }
  }

  concat::fragment { 'ossec.conf_90' :
    target  => $wazuh::params::config_file,
    content => template('wazuh/90_ossec.conf.erb'),
    order   => 90,
    notify  => Service[$wazuh::params::server_service]
  }

  if ( $manage_client_keys == true ) {
    concat { $wazuh::params::keys_file:
      owner   => $wazuh::params::keys_owner,
      group   => $wazuh::params::keys_group,
      mode    => $wazuh::params::keys_mode,
      notify  => Service[$wazuh::params::server_service],
      require => Package[$wazuh::params::server_package],
    }
    concat::fragment { 'var_ossec_etc_client.keys_end' :
      target  => $wazuh::params::keys_file,
      order   => 99,
      content => "\n",
      notify  => Service[$wazuh::params::server_service]
    }
  }

  file { '/var/ossec/etc/shared/agent.conf':
    content => template('wazuh/ossec_shared_agent.conf.erb'),
    owner   => $wazuh::params::config_owner,
    group   => $wazuh::params::config_group,
    mode    => $wazuh::params::config_mode,
    notify  => Service[$wazuh::params::server_service],
    require => Package[$wazuh::params::server_package]
  }

  Wazuh::Agentkey<<| |>>

}
