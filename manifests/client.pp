# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Setup for ossec client
# Stdlib::Absolutepath is handy but doesn't like undef
class wazuh::client(
  String $agent_package_name,
  String $agent_service_name,
  Stdlib::Absolutepath $config_file,
  Boolean $ossec_active_response    = true,
  Boolean $ossec_rootcheck          = true,
  $ossec_rootcheck_frequency        = 36000,
  $ossec_rootcheck_checkports       = true,
  $ossec_rootcheck_checkfiles       = true,
  $ossec_server_ip                  = undef,
  $ossec_server_hostname            = undef,
  $wazuh_manager_address            = undef,
  $ossec_server_port                = '1514',
  $ossec_server_protocol            = 'udp',
  $ossec_server_notify_time         = undef,
  $ossec_server_time_reconnect      = undef,
  $ossec_scanpaths                  = [],
  Array[Stdlib::Absolutepath] $ossec_ignorepaths = [],
  $ossec_ignorepaths_regex          = [],
  String $config_owner              = lookup('wazuh::config_owner'),
  String $config_group              = lookup('wazuh::config_group'),
  String $config_mode               = lookup('wazuh::config_mode'),
  String $keys_file                 = lookup('wazuh::keys_file'),
  String $keys_owner                = lookup('wazuh::keys_owner'),
  String $keys_group                = lookup('wazuh::keys_group'),
  String $keys_mode                 = lookup('wazuh::keys_mode'),
  $ossec_local_files                = {},
  $ossec_syscheck_frequency         = 43200,
  $ossec_prefilter                  = false,
  $ossec_service_provider           = lookup('wazuh::ossec_service_provider'),
  $ossec_config_profiles            = [],
  Boolean $enable_selinux_rules     = false,
  $agent_name                       = $facts['networking']['hostname'],
  $agent_ip_address                 = $facts['networking']['ip'],
  Boolean $manage_repo              = true,
  Boolean $manage_epel_repo         = false,
  String $agent_package_ensure      = 'installed',
  $agent_auto_restart               = 'yes',
  # client_buffer configuration
  $client_buffer_queue_size         = 5000,
  $client_buffer_events_per_second  = 500,
  $client_keys_management           = 'export',
  $agent_auth_password              = undef,
  Optional[Stdlib::Absolutepath] $wazuh_manager_root_ca_pem = undef,
  Optional[Stdlib::Absolutepath] $wazuh_client_pem = undef,
  Optional[Stdlib::Absolutepath] $wazuh_client_key = undef,
  String $rootCA_owner              = lookup('wazuh::keys_owner'),
  String $rootCA_group              = lookup('wazuh::keys_group'),
  String $rootCA_mode               = lookup('wazuh::keys_mode'),
  $agent_seed                       = undef,
  $max_clients                      = 3000,
  $ar_repeated_offenders            = '',
  $enable_wodle_openscap            = false,
  $wodle_openscap_content           = lookup('wazuh::wodle_openscap_content'),
  Boolean $service_has_status       = lookup('wazuh::service_has_status'),
  $ossec_conf_template              = 'wazuh/wazuh_agent.conf.erb',
  Boolean $manage_firewall          = lookup('wazuh::manage_firewall'),
) {
  # Required params
  unless defined('$ossec_server_ip', '$ossec_server_hostname', '$wazuh_manager_address') {
    fail('must pass either $ossec_server_ip or $ossec_server_hostname or $wazuh_manager_address to Class[\'wazuh::client\'].')
  }

  # Repo/package install
  case $facts['kernel'] {
    'Linux': {
      if $manage_repo {
        class { 'wazuh::repo':
          redhat_manage_epel => $manage_epel_repo,
          before             => Package[$agent_package_name],
        }
        # Could also use fancy chaining arrows
        # Class['wazuh::repo'] -> Package[$agent_package_name]
      }

      # Install package
      package { $agent_package_name:
        ensure => $agent_package_ensure
      }
      
    }
    'windows': {
      file {
        'C:/wazuh-winagent-v2.1.1-1.exe':
          owner              => 'Administrators',
          group              => 'Administrators',
          mode               => '0774',
          source             => 'puppet:///modules/wazuh/wazuh-winagent-v2.1.1-1.exe',
          source_permissions => ignore
      }

      package { $agent_package_name:
        ensure          => $agent_package_ensure,
        provider        => 'windows',
        source          => 'C:/wazuh-winagent-v2.1.1-1.exe',
        install_options => [ '/S' ],  # Nullsoft installer silent installation
        require         => File['C:/wazuh-winagent-v2.1.1-1.exe'],
      }
    }
    default: { fail('OS not supported') }
  }

  # Manage the service
  service { $agent_service_name:
    ensure    => running,
    enable    => true,
    hasstatus => $service_has_status,
    pattern   => $agent_service_name,
    #provider  => $ossec_service_provider,
    require   => Package[$agent_package_name],
  }

  # Set up configuration file and fragments
  concat { 'ossec.conf':
    path    => $config_file,
    owner   => $config_owner,
    group   => $config_group,
    mode    => $config_mode,
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
  
  # Pick whichever server address is specified first
  $ossec_server_address = pick($ossec_server_ip, $ossec_server_hostname)

  # Manage client keys/registration
  case $client_keys_management {
    'export': {
      class { 'wazuh::agentkey':
        keys_owner           => $keys_owner,
        keys_group           => $keys_group,
        keys_mode            => $keys_mode,
        max_clients          => $max_clients,
        agent_name           => $agent_name,
        agent_ip_address     => $agent_ip_address,
        ossec_server_address => $ossec_server_address,
        agent_package_name   => $agent_package_name,
        agent_service_name   => $agent_service_name,
        keys_file            => $keys_file,
        agent_seed           => $agent_seed,
        #export_keys          => $export_client_keys,
      }
    }
    'authd': {
      # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl
      # NOTE: Per the documentation, any and all of these may be used

      # Verify manager cert
      if $wazuh_manager_root_ca_pem {
        file { '/var/ossec/etc/rootCA.pem':
          owner   => $rootCA_owner,
          group   => $rootCA_group,
          mode    => $rootCA_mode,
          content => $wazuh_manager_root_ca_pem,
          require => Package[$agent_package_name],
        }
        $agent_auth_command_ca_opt = '-v /var/ossec/etc/rootCA.pem'
      }

      # Verify client cert
      if ($wazuh_client_pem and $wazuh_client_key) {
        $agent_auth_command_client_cert_opt = "-x ${wazuh_client_pem} -k ${wazuh_client_key}"
      }

      # Use password
      if $agent_auth_password {
        $agent_auth_command_passwd_opt = "-P '${agent_auth_password}'"
      }

      # Final command, rather long which is how these things usually go
      $agent_auth_command = "/var/ossec/bin/agent-auth -m ${ossec_server_address} \
                            -A ${agent_name} \
                            -D /var/ossec/ \
                            ${agent_auth_command_ca_opt} \
                            ${agent_auth_command_client_cert_opt} \
                            ${agent_auth_command_passwd_opt}"
      exec { 'agent-auth-cmd':
        command => "${agent_auth_command}",
        creates => $keys_file,
        require => Package[$agent_package_name],
        notify  => Service[$agent_service_name],
        before  => File[$keys_file]
      }
    }
    'none': {
      # Don't manage key files at all, but let user know
      notify { 'Not registering client to Wazuh server': }
    }
    default: {
      fail("You have selected an invalid client key management type: ${client_keys_management}")
    }
  }

  # SELinux rules
  # - Requires selinux module specified in metadata.json
  if ($facts['os']['family'] == 'RedHat' and $enable_selinux_rules == true) {
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
