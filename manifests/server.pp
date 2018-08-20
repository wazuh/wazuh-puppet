# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Main ossec server config
class wazuh::server (
  String $server_package,
  String $server_service,
  #String $authd_service,
  Stdlib::Absolutepath $config_file,
  Stdlib::Absolutepath $shared_agent_config_file,
  Stdlib::Absolutepath $authd_pass_file          = '/var/ossec/etc/authd.pass',
  String $config_owner                           = lookup('wazuh::config_owner'),
  String $config_group                           = lookup('wazuh::config_group'),
  String $config_mode                            = lookup('wazuh::config_mode'),
  String $keys_file                              = lookup('wazuh::keys_file'),
  String $keys_owner                             = lookup('wazuh::keys_owner'),
  String $keys_group                             = lookup('wazuh::keys_group'),
  String $keys_mode                              = lookup('wazuh::keys_mode'),
  Stdlib::Host $ossec_server_address             = $facts['networking']['fqdn'],
  String $validate_cmd_conf                      = '/var/ossec/bin/verify-agent-conf -f %',
  Stdlib::Absolutepath $processlist_file         = '/var/ossec/bin/.process_list',
  Optional[Stdlib::Host] $smtp_server            = undef,
  Array[String] $ossec_emailto                   = [],
  $ossec_emailfrom                               = "wazuh@${facts['networking']['domain']}",
  Boolean $api_service_has_status                = lookup('wazuh::service_has_status'),
  Boolean $server_service_has_status             = lookup('wazuh::service_has_status'),
  Boolean $ossec_active_response                 = true,
  Boolean $ossec_rootcheck                       = true,
  $ossec_rootcheck_frequency                     = 36000,
  Boolean $ossec_rootcheck_checkports            = true,
  Boolean $ossec_rootcheck_checkfiles            = true,
  $ossec_global_host_information_level           = 8,
  $ossec_global_stat_level                       = 8,
  $ossec_email_alert_level                       = 7,
  Array[Stdlib::Absolutepath] $ossec_ignorepaths = [],
  $ossec_ignorepaths_regex                       = [],
  $ossec_scanpaths                               = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'yes', 'realtime' => 'yes'} ],
  $ossec_white_list                              = [],
  $ossec_extra_rules_config                      = [],
  #$ossec_local_files                             = $::wazuh::params::default_local_files,
  Boolean $ossec_email_notification              = true,
  $ossec_email_maxperhour                        = '12',
  $ossec_email_idsname                           = undef,
  $ossec_syscheck_frequency                      = 79200,
  $ossec_auto_ignore                             = 'yes',
  Boolean $ossec_prefilter                       = false,
  #$ossec_service_provider                        = $::wazuh::params::ossec_service_provider,
  #$api_service_provider                          = $::wazuh::params::api_service_provider,
  $ossec_server_port                             = '1514',
  $ossec_server_protocol                         = 'udp',
  $ossec_authd_enabled                           = false,
  String $server_package_ensure                  = 'installed',
  String $api_package_ensure                     = 'installed',
  Hash $api_config_certs                         = undef,
  Hash $api_config_params                        = undef,
  Hash $api_config_advanced_params               = undef,
  Boolean $manage_repos                          = true,
  Boolean $manage_epel_repo                      = false,
  Boolean $install_wazuh_api                     = false,
  Boolean $manage_nodejs                         = true,
  Boolean $api_enable_https                      = false,
  String $api_package_name                       = undef,
  String $api_service_name                       = undef,
  Optional[Stdlib::Absolutepath] $api_server_crt = undef,
  Optional[Stdlib::Absolutepath] $api_server_key = undef,
  String $nodejs_repo_url_suffix                 = '6.x',
  $agent_auth_password                           = undef,
  $ar_repeated_offenders                         = '',
  Boolean $syslog_output                         = false,
  $syslog_output_server                          = undef,
  $syslog_output_format                          = undef,
  $enable_wodle_openscap                         = false,
  $wodle_openscap_content                        = lookup('wazuh::wodle_openscap_content'),
  $api_config_template                           = 'wazuh/api/config.js.erb',
  $local_decoder_template                        = 'wazuh/local_decoder.xml.erb',
  $local_rules_template                          = 'wazuh/local_rules.xml.erb',
  $shared_agent_template                         = 'wazuh/ossec_shared_agent.conf.erb',
  String $client_keys_management                 = 'export',
  Boolean $wazuh_manager_verify_client_ssl       = false,
  #Boolean $wazuh_manager_verify_manager_ssl      = false,
  Optional[Stdlib::Absolutepath] $wazuh_manager_root_ca_pem = undef,
  Optional[Stdlib::Absolutepath] $wazuh_manager_server_crt  = undef,
  Optional[Stdlib::Absolutepath] $wazuh_manager_server_key  = undef,
  String $rootCA_owner                           = lookup('wazuh::keys_owner'),
  String $rootCA_group                           = lookup('wazuh::keys_group'),
  String $rootCA_mode                            = lookup('wazuh::keys_mode'),
  Boolean $manage_firewall                       = false,
) {
  if ( $ossec_email_notification ) {
    # Validate required params for email notifications
    if $smtp_server == undef {
      fail('$ossec_emailnotification is enabled but $smtp_server was not set')
    }
    validate_email_address($ossec_emailfrom, $ossec_emailto)
  }

  if $facts['os']['family'] == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  # Repo configuration
  if $manage_repos {
    class { 'wazuh::repo':
      redhat_manage_epel => $manage_epel_repo,
      before             => Package[$server_package],
    }
  }

  # Install package
  package { $server_package:
    ensure  => $server_package_ensure
  }

  # Server config files
  file {
    default:
      owner   => $config_owner,
      group   => $config_group,
      mode    => $config_mode,
      notify  => Service[$server_service],
      require => Package[$server_package];
    $shared_agent_config_file:
      validate_cmd => $validate_cmd_conf,
      content      => template($shared_agent_template);
    '/var/ossec/etc/rules/local_rules.xml':
      content      => template($local_rules_template);
    '/var/ossec/etc/decoders/local_decoder.xml':
      content      => template($local_decoder_template);
    $processlist_file:
      content      => template('wazuh/process_list.erb');
  }

  concat { 'ossec.conf':
    path    => $config_file,
    owner   => $config_owner,
    group   => $config_group,
    mode    => $config_mode,
    require => Package[$server_package],
    notify  => Service[$server_service],
    #validate_cmd => $wazuh::params::validate_cmd_conf, # never implemented, see https://github.com/wazuh/wazuh/issues/86
  }

  concat::fragment {
    default:
      target => 'ossec.conf',
      notify => Service[$server_service];
    'ossec.conf_header':
      order   => 00,
      content => "<ossec_config>\n";
    'ossec.conf_agent':
      order   => 10,
      content => template('wazuh/wazuh_manager.conf.erb');
    'ossec.conf_footer':
      order   => 99,
      content => '</ossec_config>';
  }

  # Service configuration
  service { $server_service:
    ensure    => running,
    enable    => true,
    hasstatus => $server_service_has_status,
    pattern   => $server_service,
    require   => Package[$server_package],
  }

  # Client key management
  case $client_keys_management {
    'export': {
      concat { $keys_file:
        owner   => $keys_owner,
        group   => $keys_group,
        mode    => $keys_mode,
        notify  => Service[$server_service],
        require => Package[$server_package],
      }
      concat::fragment { 'var_ossec_etc_client.keys_end' :
        target  => $keys_file,
        order   => 99,
        content => "\n",
        notify  => Service[$server_service]
      }
      # Collect keys if possible
      if ($settings::storeconfigs == true) {
        Wazuh::Agentkey <<| tag == $ossec_server_address |>>
      } else {
        notify { "To collect agent keys, storeconfigs must be enabled. Current setting: ${settings::storeconfigs}" }
      }
    }
    'authd': {
      # TODO: ensure the authd service is started if client_keys_management == authd
      # (see https://github.com/wazuh/wazuh/issues/80)
      concat { 'ossec-authd':
        path    => '/etc/sysconfig/ossec-authd',
        owner   => 'root',
        group   => 'ossec',
        mode    => '0640',
        require => Package[$server_package],
        #notify  => Service[$authd_service],
      }
      concat::fragment { 'authd-start':
        target  => 'ossec-authd',
        content => 'AUTHD_OPTS="',
        order   => 00,
      }
      concat::fragment { 'authd-end':
        target  => 'ossec-authd',
        content => "\"\n",
        order   => 99,
      }

      # Use password
      if defined('$agent_auth_password') {
        file { $authd_pass_file:
          owner   => $keys_owner,
          group   => $keys_group,
          mode    => $keys_mode,
          content => $agent_auth_password,
          require => Package[$server_package],
          #notify  => Service[$authd_service],
        }
        # TODO: Add start option to systemd file
        concat::fragment { 'authd-passwd':
          target  => 'ossec-authd',
          content => '-P',
          order   => 10,
        }
      }

      # Configure server side certs if specified
      # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl
      if ($wazuh_manager_server_key and $wazuh_manager_server_crt) {
        file { '/var/ossec/etc/sslmanager.key':
          owner   => 'root',
          group   => 'ossec',
          mode    => '0640',
          content => $wazuh_manager_server_key,
          require => Package[$server_package],
          notify  => Service[$server_service],
        }

        file { '/var/ossec/etc/sslmanager.cert':
          owner   => 'root',
          group   => 'ossec',
          mode    => '0640',
          content => $wazuh_manager_server_crt,
          require => Package[$server_package],
          notify  => Service[$server_service],
        }
      }

      # Verify client certs
      if $wazuh_manager_root_ca_pem {
        file { '/var/ossec/etc/rootCA.pem':
          owner   => $rootCA_owner,
          group   => $rootCA_group,
          mode    => $rootCA_mode,
          content => $wazuh_manager_root_ca_pem,
          require => Package[$server_package],
          #notify  => Service[$authd_service],
        }
        # TODO: Add start option to systemd file
        concat::fragment { 'authd-verify_client_loose':
          target  => 'ossec-authd',
          content => ' -v /var/ossec/etc/rootCA.pem',
          order   => 20,
        }

        # NOTE: -s implies -v
        # TODO: Add start option to systemd file
        if $wazuh_manager_verify_client_ssl {
          concat::fragment { 'authd-verify_client_strict':
            target  => 'ossec-authd',
            content => ' -s',
            order   => 30,
          }
        }
      }
    }
    'none': {
      # Don't manage key file at all, but let user know
      notify { 'Not managing client keys': }
    }
    default: {
      fail("You have selected an invalid client key management type: ${client_keys_management}")
    }
  }

  # Wazuh API
  if $install_wazuh_api {
    unless $api_package_name {
      fail('You have chosen to install the Wazuh API, but no package name has been specified')
    }
    unless $api_service_name {
      fail('You have chosen to install the Wazuh API, but no service name has been specified')
    }

    # Manage nodejs
    if $manage_nodejs {
      class { '::nodejs': repo_url_suffix => $nodejs_repo_url_suffix }
      Class['nodejs'] -> Package[$api_package_name]
    }

    # Install the API package
    package { $api_package_name:
      ensure  => $api_package_ensure
    }

    # Enable https for API
    if $api_enable_https {
      file { '/var/ossec/api/configuration/ssl/server.key':
        owner   => 'root',
        group   => 'ossec',
        mode    => '0600',
        content => $api_server_key,
        require => Package[$api_package_name],
        notify  => Service[$api_service_name],
      }

      file { '/var/ossec/api/configuration/ssl/server.crt':
        owner   => 'root',
        group   => 'ossec',
        mode    => '0600',
        content => $api_server_crt,
        require => Package[$api_package_name],
        notify  => Service[$api_service_name],
      }
    }

    # wazuh-api config.js
    # this hash is currently only covering the basic config section of config.js
    # TODO: allow customization of the entire config.js
    # for reference: https://documentation.wazuh.com/current/user-manual/api/configuration.html
    file { '/var/ossec/api/configuration/config.js':
      owner   => 'root',
      group   => 'ossec',
      mode    => '0750',
      content => template($api_config_template),
      require => Package[$api_package_name],
      notify  => Service[$api_service_name],
    }

    # Start API service
    service { $api_service_name:
      ensure    => 'running',
      enable    => true,
      hasstatus => $api_service_has_status,
      pattern   => $api_service_name,
      #provider  => $api_service_provider,
      require   => Package[$api_package_name],
    }
  }

  # Manage firewall
  if $manage_firewall {
    include firewall
    firewall { '1514 wazuh-manager':
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
