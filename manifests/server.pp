# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Main ossec server config
class wazuh::server (
  $smtp_server                         = undef,
  $ossec_emailto                       = [],
  $ossec_emailfrom                     = "wazuh@${::domain}",
  $ossec_active_response               = true,
  $ossec_rootcheck                     = true,
  $ossec_rootcheck_frequency           = 36000,
  $ossec_rootcheck_checkports          = true,
  $ossec_rootcheck_checkfiles          = true,
  $ossec_global_host_information_level = 8,
  $ossec_global_stat_level             = 8,
  $ossec_email_alert_level             = 7,
  $ossec_ignorepaths                   = [],
  $ossec_ignorepaths_regex             = [],
  $ossec_scanpaths                     = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'yes', 'realtime' => 'yes'} ],
  $ossec_white_list                    = [],
  $ossec_extra_rules_config            = [],
  $ossec_local_files                   = $::wazuh::params::default_local_files,
  $ossec_emailnotification             = true,
  $ossec_email_maxperhour              = '12',
  $ossec_email_idsname                 = undef,
  $ossec_syscheck_frequency            = 79200,
  $ossec_auto_ignore                   = 'yes',
  $ossec_prefilter                     = false,
  $ossec_service_provider              = $::wazuh::params::ossec_service_provider,
  $api_service_provider                = $::wazuh::params::api_service_provider,
  $ossec_server_port                   = '1514',
  $ossec_server_protocol               = 'udp',
  $ossec_authd_enabled                 = true,
  $ossec_integratord_enabled           = false,
  $server_package_version              = 'installed',
  $api_package_version                 = 'installed',
  $api_config_params                   = $::wazuh::params::api_config_params,
  $manage_repos                        = true,
  $manage_epel_repo                    = true,
  $manage_client_keys                  = 'authd',
  $install_wazuh_api                   = false,
  $wazuh_api_enable_https              = false,
  $wazuh_api_server_crt                = undef,
  $wazuh_api_server_key                = undef,
  $manage_nodejs                       = true,
  $nodejs_repo_url_suffix              = '6.x',
  $agent_auth_password                 = undef,
  $ar_repeated_offenders               = '',
  $syslog_output                       = false,
  $syslog_output_server                = undef,
  $syslog_output_format                = undef,
  $enable_wodle_openscap               = false,
  $wodle_openscap_content              = $::wazuh::params::wodle_openscap_content,
  $local_decoder_template              = 'wazuh/local_decoder.xml.erb',
  $decoder_exclude                     = [],
  $local_rules_template                = 'wazuh/local_rules.xml.erb',
  $rule_exclude                        = [],
  $shared_agent_template               = 'wazuh/ossec_shared_agent.conf.erb',
  $api_config_template                 = 'wazuh/api/config.js.erb',
  $wazuh_manager_verify_manager_ssl    = false,
  $wazuh_manager_server_crt            = undef,
  $wazuh_manager_server_key            = undef,
  Boolean $manage_firewall             = $::wazuh::params::manage_firewall,
) inherits wazuh::params {
  validate_bool(
    $ossec_active_response, $ossec_rootcheck,
    $manage_repos, $manage_epel_repo, $syslog_output,
    $install_wazuh_api, $wazuh_manager_verify_manager_ssl
  )
  validate_array(
    $decoder_exclude, $rule_exclude
  )

  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  validate_array($ossec_ignorepaths)
  if ( $ossec_emailnotification ) {
    if $smtp_server == undef {
      fail('$ossec_emailnotification is enabled but $smtp_server was not set')
    }
    validate_string($smtp_server)
    validate_string($ossec_emailfrom)
    validate_array($ossec_emailto)
  }

  if $::osfamily == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  if $manage_repos {
    # TODO: Allow filtering of EPEL requirement
    class { 'wazuh::repo': redhat_manage_epel => $manage_epel_repo }
    if $::osfamily == 'Debian' {
      Class['wazuh::repo'] -> Class['apt::update'] -> Package[$wazuh::params::server_package]
    } else {
      Class['wazuh::repo'] -> Package[$wazuh::params::server_package]
    }

    # install package
    package { $wazuh::params::server_package:
      ensure  => $server_package_version
    }
  }

  file {
    default:
      owner   => $wazuh::params::config_owner,
      group   => $wazuh::params::config_group,
      mode    => $wazuh::params::config_mode,
      notify  => Service[$wazuh::params::server_service],
      require => Package[$wazuh::params::server_package];
    $wazuh::params::shared_agent_config_file:
      validate_cmd => $wazuh::params::validate_cmd_conf,
      content      => template($shared_agent_template);
    '/var/ossec/etc/rules/local_rules.xml':
      content      => template($local_rules_template);
    '/var/ossec/etc/decoders/local_decoder.xml':
      content      => template($local_decoder_template);
    $wazuh::params::processlist_file:
      content      => template('wazuh/process_list.erb');
  }

  service { $wazuh::params::server_service:
    ensure    => running,
    enable    => true,
    hasstatus => $wazuh::params::service_has_status,
    pattern   => $wazuh::params::server_service,
    provider  => $ossec_service_provider,
    require   => Package[$wazuh::params::server_package],
  }

  concat { 'ossec.conf':
    path    => $wazuh::params::config_file,
    owner   => $wazuh::params::config_owner,
    group   => $wazuh::params::config_group,
    mode    => $wazuh::params::config_mode,
    require => Package[$wazuh::params::server_package],
    notify  => Service[$wazuh::params::server_service],
    #validate_cmd => $wazuh::params::validate_cmd_conf, # not yet implemented, see https://github.com/wazuh/wazuh/issues/86
  }

  concat::fragment {
    default:
      target => 'ossec.conf',
      notify => Service[$wazuh::params::server_service];
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

  if ( $manage_client_keys == 'export' ) {
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
    # A separate module to avoid storeconfigs warnings when not managing keys
    include wazuh::collect_agent_keys
  }



  if ( $manage_client_keys == 'authd') {
    # TODO: ensure the authd service is started if manage_client_keys == authd
    # (see https://github.com/wazuh/wazuh/issues/80)

    file { $wazuh::params::authd_pass_file:
      owner   => $wazuh::params::keys_owner,
      group   => $wazuh::params::keys_group,
      mode    => $wazuh::params::keys_mode,
      content => $agent_auth_password,
      require => Package[$wazuh::params::server_package],
    }
  }

  # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl
  if $wazuh_manager_verify_manager_ssl {
    validate_string(
      $wazuh_manager_server_crt, $wazuh_manager_server_key
    )

    file { '/var/ossec/etc/sslmanager.key':
      content => $wazuh_manager_server_key,
      owner   => 'root',
      group   => 'ossec',
      mode    => '0640',
      require => Package[$wazuh::params::server_package],
      notify  => Service[$wazuh::params::server_service],
    }

    file { '/var/ossec/etc/sslmanager.cert':
      content => $wazuh_manager_server_crt,
      owner   => 'root',
      group   => 'ossec',
      mode    => '0640',
      require => Package[$wazuh::params::server_package],
      notify  => Service[$wazuh::params::server_service],
    }

  }

  ### Wazuh API
  if $install_wazuh_api {
    validate_bool($manage_nodejs)
    if $manage_nodejs {
      validate_string($nodejs_repo_url_suffix)
      class { '::nodejs': repo_url_suffix => $nodejs_repo_url_suffix }
      Class['nodejs'] -> Package[$wazuh::params::api_package]
    }

    package { $wazuh::params::api_package:
      ensure  => $api_package_version
    }

    if $wazuh_api_enable_https {
      validate_string($wazuh_api_server_crt, $wazuh_api_server_key)
      file { '/var/ossec/api/configuration/ssl/server.key':
        content => $wazuh_api_server_key,
        owner   => 'root',
        group   => 'ossec',
        mode    => '0600',
        require => Package[$wazuh::params::api_package],
        notify  => Service[$wazuh::params::api_service],
      }

      file { '/var/ossec/api/configuration/ssl/server.crt':
        content => $wazuh_api_server_crt,
        owner   => 'root',
        group   => 'ossec',
        mode    => '0600',
        require => Package[$wazuh::params::api_package],
        notify  => Service[$wazuh::params::api_service],
      }
    }

    # wazuh-api config.js
    # this hash is currently only covering the basic config section of config.js
    # TODO: allow customization of the entire config.js
    # for reference: https://documentation.wazuh.com/current/user-manual/api/configuration.html
    file { '/var/ossec/api/configuration/config.js':
      content => template($api_config_template),
      owner   => 'root',
      group   => 'ossec',
      mode    => '0750',
      require => Package[$wazuh::params::api_package],
      notify  => Service[$wazuh::params::api_service],
    }

    service { $wazuh::params::api_service:
      ensure    => running,
      enable    => true,
      hasstatus => $wazuh::params::service_has_status,
      pattern   => $wazuh::params::api_service,
      provider  => $api_service_provider,
      require   => Package[$wazuh::params::api_package],
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
