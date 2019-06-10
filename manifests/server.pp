# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Main ossec server config
class wazuh::server (

  $ossec_active_response               = true,


  ### Ossec.conf blocks

  ## Email notifications

  $smtp_server                         = undef,
  $ossec_emailto                       = [],
  $ossec_emailfrom                     = "wazuh@${::domain}",
  $ossec_emailnotification             = false,
  $ossec_email_maxperhour              = '12',
  $ossec_email_idsname                 = undef,
  $ossec_email_alert_level             = 12,

  ## Rootcheck

  $ossec_rootcheck_disabled            = true,
  $ossec_rootcheck_check_files         = "yes",
  $ossec_rootcheck_check_trojans       = "yes",
  $ossec_rootcheck_check_dev           = "yes",
  $ossec_rootcheck_check_sys           = "yes",
  $ossec_rootcheck_check_pids          = "yes",
  $ossec_rootcheck_check_ports         = "yes",
  $ossec_rootcheck_check_if            = "yes",
  $ossec_rootcheck_frequency           = 43200,
  $ossec_rootcheck_rootkit_files       = "/var/ossec/etc/rootcheck/rootkit_files.txt",
  $ossec_rootcheck_rootkit_trojans     = "/var/ossec/etc/rootcheck/rootkit_trojans.txt",
  $ossec_rootcheck_skip_nfs            = "yes",
  
  ## Wodles

  #openscap
  $wodle_openscap_disabled             = true,
  $wodle_openscap_timeout              = "1800",
  $wodle_openscap_interval             = "1d",
  $wodle_openscap_scan_on_start        = "yes",
  $wodle_openscap_content              = $::wazuh::params::wodle_openscap_content,
  
  #cis-cat
  $wodle_ciscat_disabled               = true,
  $wodle_ciscat_timeout                = "1800",
  $wodle_ciscat_interval               = "1d",
  $wodle_ciscat_scan_on_start          = "yes",
  $wodle_ciscat_java_path              = "wodles/java",
  $wodle_ciscat_ciscat_path            = "wodles/ciscat",

  #osquery

  $wodle_osquery_disabled             = true,
  $wodle_osquery_run_daemon           = "yes",
  $wodle_osquery_log_path             = "/var/log/osquery/osqueryd.results.log",
  $wodle_osquery_config_path          = "/etc/osquery/osquery.conf",
  $wodle_osquery_add_labels           = "yes",

  #syscollector
  $wodle_syscollector_disabled        = true,
  $wodle_syscollector_interval        = "1h",
  $wodle_syscollector_scan_on_start   = "yes",
  $wodle_syscollector_hardware        = "yes",
  $wodle_syscollector_os              = "yes",
  $wodle_syscollector_network         = "yes",
  $wodle_syscollector_packages        = "yes",
  $wodle_syscollector_ports           = "yes",
  $wodle_syscollector_processes       = "yes",

  #vulnerability-detector

  $wodle_vulnerability_detector_disabled             = true,
  $wodle_vulnerability_detector_interval             = "5m",
  $wodle_vulnerability_detector_ignore_time          = "6h",
  $wodle_vulnerability_detector_run_on_start         = "yes",
  $wodle_vulnerability_detector_ubuntu_disabled      = "yes",
  $wodle_vulnerability_detector_ubuntu_update        = "1h",
  $wodle_vulnerability_detector_redhat_disable       = "yes",
  $wodle_vulnerability_detector_redhat_update_from   = "2010",
  $wodle_vulnerability_detector_redhat_update        = "1h",
  $wodle_vulnerability_detector_debian_9_disable     = "yes",
  $wodle_vulnerability_detector_debian_9_update      = "1h",

  # syslog

  $syslog_output                       = false,
  $syslog_output_level                 = 2,
  $syslog_output_port                  = 514,
  $syslog_output_server                = undef,
  $syslog_output_format                = undef,

  ### Wazuh-API

  $api_service_provider                = $::wazuh::params::api_service_provider,
  $api_package_version                 = 'installed',
  $api_config_params                   = $::wazuh::params::api_config_params,
  $api_config_template                 = 'wazuh/api/config.js.erb',
  $install_wazuh_api                   = false,
  $wazuh_api_enable_https              = false,
  $wazuh_api_server_crt                = undef,
  $wazuh_api_server_key                = undef,


  $ossec_ignorepaths                   = [],
  $ossec_ignorepaths_regex             = [],
  $ossec_scanpaths                     = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'yes', 'realtime' => 'yes'} ],
  $ossec_white_list                    = [],
  $ossec_extra_rules_config            = [],
  $ossec_local_files                   = $::wazuh::params::default_local_files,

  $ossec_syscheck_frequency            = 79200,
  $ossec_auto_ignore                   = 'yes',
  $ossec_prefilter                     = false,
  $ossec_service_provider              = $::wazuh::params::ossec_service_provider,
  
  $ossec_server_port                   = '1514',
  $ossec_server_protocol               = 'udp',
  $ossec_integratord_enabled           = false,
  $server_package_version              = '3.9.1-1',
  
  
  $manage_repos                        = true,
  $manage_epel_repo                    = true,
  $manage_client_keys                  = 'authd',
  $agent_auth_password                 = undef,
  $ar_repeated_offenders               = '',

  $local_decoder_template              = 'wazuh/local_decoder.xml.erb',
  $decoder_exclude                     = [],
  $local_rules_template                = 'wazuh/local_rules.xml.erb',
  $rule_exclude                        = [],
  $shared_agent_template               = 'wazuh/ossec_shared_agent.conf.erb',
  
  $wazuh_manager_verify_manager_ssl    = false,
  $wazuh_manager_server_crt            = undef,
  $wazuh_manager_server_key            = undef,
  $ossec_auth_ssl_cert                 = undef,
  $ossec_auth_ssl_key                  = undef,
  $ossec_auth_ssl_ca                   = undef,
  Boolean $manage_firewall             = $::wazuh::params::manage_firewall,
  Integer $ossec_auth_port             = 1515,
  Boolean $ossec_auth_use_srcip        = false,
  Boolean $ossec_auth_use_password     = false,
  Boolean $ossec_auth_force_insert     = false,
  Boolean $ossec_auth_purge            = false,
) inherits wazuh::params {
  validate_bool(
    $ossec_active_response,$manage_repos, $manage_epel_repo, $syslog_output,
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

  # Install wazuh-repository

  if $manage_repos {
    # TODO: Allow filtering of EPEL requirement
    class { 'wazuh::repo': redhat_manage_epel => $manage_epel_repo }
    if $::osfamily == 'Debian' {
      Class['wazuh::repo'] -> Class['apt::update'] -> Package[$wazuh::params::server_package]
    } else {
      Class['wazuh::repo'] -> Package[$wazuh::params::server_package]
    }
  }

  # Install and configure Wazuh-manager package

  package { $wazuh::params::server_package:
    ensure  => $server_package_version, # lint:ignore:security_package_pinned_version
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

  ## Declaring variables for localfile and wodles generation
  
  if $::osfamily == 'Debian' {
    $apply_template_os = "debian"
  }else{
    $apply_template_os = "centos"
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

    if ($wazuh_manager_server_crt != undef) and ($wazuh_manager_server_key != undef) {
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
