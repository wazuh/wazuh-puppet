# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Setup for ossec client
class wazuh::client(
  $ossec_active_response           = true,
  $ossec_rootcheck                 = true,
  $ossec_rootcheck_frequency       = 36000,
  $ossec_rootcheck_checkports      = true,
  $ossec_rootcheck_checkfiles      = true,
  $ossec_server_ip                 = undef,
  $ossec_server_hostname           = undef,
  $wazuh_manager_address           = undef,
  $ossec_server_port               = '1514',
  $ossec_server_protocol           = 'udp',
  $ossec_server_notify_time        = undef,
  $ossec_server_time_reconnect     = undef,
  $ossec_scanpaths                 = [],
  $ossec_ignorepaths               = [],
  $ossec_ignorepaths_regex         = [],
  $ossec_local_files               = $::wazuh::params::default_local_files,
  $ossec_syscheck_frequency        = 43200,
  $ossec_prefilter                 = false,
  $ossec_service_provider          = $::wazuh::params::ossec_service_provider,
  $ossec_config_profiles           = [],
  $selinux                         = false,
  $agent_name                      = $::hostname,
  $agent_ip_address                = $::ipaddress,
  $agent_group                     = 'default',
  $manage_repo                     = true,
  $manage_epel_repo                = true,
  $agent_package_name              = $::wazuh::params::agent_package,
  $agent_package_version           = 'installed',
  $agent_service_name              = $::wazuh::params::agent_service,
  $agent_auto_restart              = 'yes',
  # client_buffer configuration
  $client_buffer_queue_size        = 5000,
  $client_buffer_events_per_second = 500,
  $manage_client_keys              = 'authd',
  $agent_auth_password             = undef,
  $wazuh_manager_root_ca_pem       = undef,
  $agent_seed                      = undef,
  $max_clients                     = 3000,
  $ar_repeated_offenders           = '',
  $enable_wodle_openscap           = false,
  $wodle_openscap_content          = $::wazuh::params::wodle_openscap_content,
  $service_has_status              = $::wazuh::params::service_has_status,
  $ossec_conf_template             = 'wazuh/wazuh_agent.conf.erb',
  Boolean $manage_firewall         = $::wazuh::params::manage_firewall,
) inherits wazuh::params {
  validate_bool(
    $ossec_active_response, $ossec_rootcheck,
    $selinux, $manage_repo, $manage_epel_repo
  )
  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  validate_array($ossec_ignorepaths)
  validate_string($agent_package_name)
  validate_string($agent_service_name)

  if ( ( $ossec_server_ip == undef ) and ( $ossec_server_hostname == undef ) and ( $wazuh_manager_address == undef ) ) {
    fail('must pass either $ossec_server_ip or $ossec_server_hostname or $wazuh_manager_address to Class[\'wazuh::client\'].')
  }

  case $::kernel {
    'Linux' : {
      if $manage_repo {
        class { 'wazuh::repo': redhat_manage_epel => $manage_epel_repo }
        if $::osfamily == 'Debian' {
          Class['wazuh::repo'] -> Class['apt::update'] -> Package[$agent_package_name]
        } else {
          Class['wazuh::repo'] -> Package[$agent_package_name]
        }
      }
      package { $agent_package_name:
        ensure => $agent_package_version, # lint:ignore:security_package_pinned_version
      }
    }
    'windows' : {

      file {
        'C:/wazuh-agent-3.7.2-1.msi':
          owner              => 'Administrators',
          group              => 'Administrators',
          mode               => '0774',
          source             => 'puppet:///modules/wazuh/wazuh-agent-3.7.2-1.msi',
          source_permissions => ignore
      }
      if ( $manage_client_keys == 'authd' ) {
        package { $agent_package_name:
          ensure          => $agent_package_version, # lint:ignore:security_package_pinned_version
          provider        => 'windows',
          source          => 'C:/wazuh-agent-3.7.2-1.msi',
          install_options => [ '/q', "ADDRESS=${ossec_server_ip}", "AUTHD_SERVER=${ossec_server_ip}" ],  # silent installation
          require         => File['C:/wazuh-agent-3.7.2-1.msi'],
        }
      }
      else {
        package { $agent_package_name:
          ensure          => $agent_package_version, # lint:ignore:security_package_pinned_version
          provider        => 'windows',
          source          => 'C:/wazuh-agent-3.7.2-1.msi',
          install_options => [ '/q' ],  # silent installation
          require         => File['C:/wazuh-agent-3.7.2-1.msi'],
        }
      }
    }
    default: { fail('OS not supported') }
  }

  service { $agent_service_name:
    ensure    => running,
    enable    => true,
    hasstatus => $service_has_status,
    pattern   => $agent_service_name,
    provider  => $ossec_service_provider,
    require   => Package[$agent_package_name],
  }

  concat { 'ossec.conf':
    path    => $wazuh::params::config_file,
    owner   => $wazuh::params::config_owner,
    group   => $wazuh::params::config_group,
    mode    => $wazuh::params::config_mode,
    require => Package[$agent_package_name],
    notify  => Service[$agent_service_name],
  }

  concat::fragment {
    default:
      target => 'ossec.conf',
      notify => Service[$agent_service_name];
    'ossec.conf_header':
      order   => 00,
      content => "<ossec_config>\n";
    'ossec.conf_agent':
      order   => 10,
      content => template($ossec_conf_template);
    'ossec.conf_footer':
      order   => 99,
      content => '</ossec_config>';
  }

  if ( $manage_client_keys == 'export' ) {
    concat { $wazuh::params::keys_file:
      owner   => $wazuh::params::keys_owner,
      group   => $wazuh::params::keys_group,
      mode    => $wazuh::params::keys_mode,
      notify  => Service[$agent_service_name],
      require => Package[$agent_package_name]
    }
    # A separate module to avoid storeconfigs warnings when not managing keys
    class { 'wazuh::export_agent_key':
      max_clients      => $max_clients,
      agent_name       => $agent_name,
      agent_ip_address => $agent_ip_address,
      agent_seed       => $agent_seed,
    }
  } elsif ($manage_client_keys == 'authd') {
    if ($::kernel == 'Linux') {
    
      # Is this really Linux only?
      $ossec_server_address = pick($ossec_server_ip, $ossec_server_hostname)

      file { $::wazuh::params::keys_file:
        owner => $wazuh::params::keys_owner,
        group => $wazuh::params::keys_group,
        mode  => $wazuh::params::keys_mode,
      }

      # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl

      $agent_auth_base_command = "/var/ossec/bin/agent-auth -m ${ossec_server_address} -A ${agent_name} -G ${agent_group} -D /var/ossec/"
      if $wazuh_manager_root_ca_pem != undef {
        validate_string($wazuh_manager_root_ca_pem)
        file { '/var/ossec/etc/rootCA.pem':
          owner   => $wazuh::params::keys_owner,
          group   => $wazuh::params::keys_group,
          mode    => $wazuh::params::keys_mode,
          content => $wazuh_manager_root_ca_pem,
          require => Package[$agent_package_name],
        }

        $agent_auth_command = "${agent_auth_base_command} -v /var/ossec/etc/rootCA.pem"
      } else {
        $agent_auth_command = $agent_auth_base_command
      }

      if $agent_auth_password {
        exec { 'agent-auth-with-pwd':
          command => "${agent_auth_command} -P '${agent_auth_password}'",
          unless  => "/bin/egrep -q '.' ${::wazuh::params::keys_file}",
          require => Package[$agent_package_name],
          notify  => Service[$agent_service_name],
          before  => File[$wazuh::params::keys_file]
       }
      } else {
        exec { 'agent-auth-without-pwd':
          command => $agent_auth_command,
          unless  => "/bin/egrep -q '.' ${::wazuh::params::keys_file}",
          require => Package[$agent_package_name],
          notify  => Service[$agent_service_name],
          before  => File[$wazuh::params::keys_file],
        }
      }
    }
  }

  # SELinux
  # Requires selinux module specified in metadata.json
  if ($::osfamily == 'RedHat' and $selinux == true) {
    selinux::module { 'ossec-logrotate':
      ensure    => 'present',
      source_te => 'puppet:///modules/wazuh/ossec-logrotate.te',
    }
  }
  # Manage firewall
  if $manage_firewall {
    include firewall
    firewall { '1514 wazuh-agent':
      dport  => $ossec_server_port,
      proto  => $ossec_server_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED'],
    }
  }
}
