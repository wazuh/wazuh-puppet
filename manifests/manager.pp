# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Main ossec server config
class wazuh::manager (

    # Installation

      $server_package_version           = $wazuh::params_manager::server_package_version,
      $manage_repos                     = $::wazuh::params_manager::manage_repos,
      $manage_firewall                  = $wazuh::params_manager::manage_firewall,


    ### Ossec.conf blocks

      ## Global

      $ossec_emailnotification          = $wazuh::params_manager::ossec_emailnotification,
      $ossec_emailto                    = $wazuh::params_manager::ossec_emailto,
      $ossec_smtp_server                = $wazuh::params_manager::ossec_smtp_server,
      $ossec_emailfrom                  = $wazuh::params_manager::ossec_emailfrom,
      $ossec_email_maxperhour           = $wazuh::params_manager::ossec_email_maxperhour,
      $ossec_email_idsname              = $wazuh::params_manager::ossec_email_idsname,
      $ossec_white_list                 = $wazuh::params_manager::ossec_white_list,
      $ossec_alert_level                = $wazuh::params_manager::ossec_alert_level,
      $ossec_email_alert_level          = $wazuh::params_manager::ossec_email_alert_level,
      $ossec_remote_connection          = $wazuh::params_manager::ossec_remote_connection,
      $ossec_remote_port                = $wazuh::params_manager::ossec_remote_port,
      $ossec_remote_protocol            = $wazuh::params_manager::ossec_remote_protocol,
      $ossec_remote_queue_size          = $wazuh::params_manager::ossec_remote_queue_size,

      # ossec.conf generation parameters

      $configure_rootcheck                  = $wazuh::params_manager::configure_rootcheck,
      $configure_wodle_openscap             = $wazuh::params_manager::configure_wodle_openscap,
      $configure_wodle_cis_cat              = $wazuh::params_manager::configure_wodle_cis_cat,
      $configure_wodle_osquery              = $wazuh::params_manager::configure_wodle_osquery,
      $configure_wodle_syscollector         = $wazuh::params_manager::configure_wodle_syscollector,
      $configure_vulnerability_detector     = $wazuh::params_manager::configure_vulnerability_detector,
      $configure_sca                        = $wazuh::params_manager::configure_sca,
      $configure_syscheck                   = $wazuh::params_manager::configure_syscheck,
      $configure_command                    = $wazuh::params_manager::configure_command,
      $configure_localfile                  = $wazuh::params_manager::configure_localfile,
      $configure_ruleset                    = $wazuh::params_manager::configure_ruleset,
      $configure_auth                       = $wazuh::params_manager::configure_auth,
      $configure_cluster                    = $wazuh::params_manager::configure_cluster,
      $configure_active_response            = $wazuh::params_manager::configure_active_response,

    # ossec.conf templates paths
      $ossec_manager_template                       = $wazuh::params_manager::ossec_manager_template,
      $ossec_rootcheck_template                     = $wazuh::params_manager::ossec_rootcheck_template,
      $ossec_wodle_openscap_template                = $wazuh::params_manager::ossec_wodle_openscap_template,
      $ossec_wodle_cis_cat_template                 = $wazuh::params_manager::ossec_wodle_cis_cat_template,
      $ossec_wodle_osquery_template                 = $wazuh::params_manager::ossec_wodle_osquery_template,
      $ossec_wodle_syscollector_template            = $wazuh::params_manager::ossec_wodle_syscollector_template,
      $ossec_wodle_vulnerability_detector_template  = $wazuh::params_manager::ossec_wodle_vulnerability_detector_template,
      $ossec_sca_template                           = $wazuh::params_manager::ossec_sca_template,
      $ossec_syscheck_template                      = $wazuh::params_manager::ossec_syscheck_template,
      $ossec_default_commands_template              = $wazuh::params_manager::ossec_default_commands_template,
      $ossec_localfile_template                     = $wazuh::params_manager::ossec_localfile_template,
      $ossec_ruleset_template                       = $wazuh::params_manager::ossec_ruleset_template,
      $ossec_auth_template                          = $wazuh::params_manager::ossec_auth_template,
      $ossec_cluster_template                       = $wazuh::params_manager::ossec_cluster_template,
      $ossec_active_response_template               = $wazuh::params_manager::ossec_active_response_template,

      ## Rootcheck

      $ossec_rootcheck_disabled             = $wazuh::params_manager::ossec_rootcheck_disabled,
      $ossec_rootcheck_check_files          = $wazuh::params_manager::ossec_rootcheck_check_files,
      $ossec_rootcheck_check_trojans        = $wazuh::params_manager::ossec_rootcheck_check_trojans,
      $ossec_rootcheck_check_dev            = $wazuh::params_manager::ossec_rootcheck_check_dev,
      $ossec_rootcheck_check_sys            = $wazuh::params_manager::ossec_rootcheck_check_sys,
      $ossec_rootcheck_check_pids           = $wazuh::params_manager::ossec_rootcheck_check_pids,
      $ossec_rootcheck_check_ports          = $wazuh::params_manager::ossec_rootcheck_check_ports,
      $ossec_rootcheck_check_if             = $wazuh::params_manager::ossec_rootcheck_check_if,
      $ossec_rootcheck_frequency            = $wazuh::params_manager::ossec_rootcheck_frequency,
      $ossec_rootcheck_rootkit_files        = $wazuh::params_manager::ossec_rootcheck_rootkit_files,
      $ossec_rootcheck_rootkit_trojans      = $wazuh::params_manager::ossec_rootcheck_rootkit_trojans,
      $ossec_rootcheck_skip_nfs             = $wazuh::params_manager::ossec_rootcheck_skip_nfs,

      ## Wodles

      #openscap
      $wodle_openscap_disabled              = $wazuh::params_manager::wodle_openscap_disabled,
      $wodle_openscap_timeout               = $wazuh::params_manager::wodle_openscap_timeout,
      $wodle_openscap_interval              = $wazuh::params_manager::wodle_openscap_interval,
      $wodle_openscap_scan_on_start         = $wazuh::params_manager::wodle_openscap_scan_on_start,

      #cis-cat
      $wodle_ciscat_disabled                = $wazuh::params_manager::wodle_ciscat_disabled,
      $wodle_ciscat_timeout                 = $wazuh::params_manager::wodle_ciscat_timeout,
      $wodle_ciscat_interval                = $wazuh::params_manager::wodle_ciscat_interval,
      $wodle_ciscat_scan_on_start           = $wazuh::params_manager::wodle_ciscat_scan_on_start,
      $wodle_ciscat_java_path               = $wazuh::params_manager::wodle_ciscat_java_path,
      $wodle_ciscat_ciscat_path             = $wazuh::params_manager::wodle_ciscat_ciscat_path,

      #osquery
      $wodle_osquery_disabled               = $wazuh::params_manager::wodle_osquery_disabled,
      $wodle_osquery_run_daemon             = $wazuh::params_manager::wodle_osquery_run_daemon,
      $wodle_osquery_log_path               = $wazuh::params_manager::wodle_osquery_log_path,
      $wodle_osquery_config_path            = $wazuh::params_manager::wodle_osquery_config_path,
      $wodle_osquery_add_labels             = $wazuh::params_manager::wodle_osquery_add_labels,

      #syscollector
      $wodle_syscollector_disabled          = $wazuh::params_manager::wodle_syscollector_disabled,
      $wodle_syscollector_interval          = $wazuh::params_manager::wodle_syscollector_interval,
      $wodle_syscollector_scan_on_start     = $wazuh::params_manager::wodle_syscollector_scan_on_start,
      $wodle_syscollector_hardware          = $wazuh::params_manager::wodle_syscollector_hardware,
      $wodle_syscollector_os                = $wazuh::params_manager::wodle_syscollector_os,
      $wodle_syscollector_network           = $wazuh::params_manager::wodle_syscollector_network,
      $wodle_syscollector_packages          = $wazuh::params_manager::wodle_syscollector_packages,
      $wodle_syscollector_ports             = $wazuh::params_manager::wodle_syscollector_ports,
      $wodle_syscollector_processes         = $wazuh::params_manager::wodle_syscollector_processes,

      #vulnerability-detector
      $wodle_vulnerability_detector_disabled                = $wazuh::params_manager::wodle_vulnerability_detector_disabled,
      $wodle_vulnerability_detector_interval                = $wazuh::params_manager::wodle_vulnerability_detector_interval,
      $wodle_vulnerability_detector_ignore_time             = $wazuh::params_manager::wodle_vulnerability_detector_ignore_time,
      $wodle_vulnerability_detector_run_on_start            = $wazuh::params_manager::wodle_vulnerability_detector_run_on_start,
      $wodle_vulnerability_detector_ubuntu_disabled         = $wazuh::params_manager::wodle_vulnerability_detector_ubuntu_disabled,
      $wodle_vulnerability_detector_ubuntu_update           = $wazuh::params_manager::wodle_vulnerability_detector_ubuntu_update,
      $wodle_vulnerability_detector_redhat_disable          = $wazuh::params_manager::wodle_vulnerability_detector_redhat_disable,
      $wodle_vulnerability_detector_redhat_update_from      = $wazuh::params_manager::wodle_vulnerability_detector_redhat_update_from,
      $wodle_vulnerability_detector_redhat_update           = $wazuh::params_manager::wodle_vulnerability_detector_redhat_update,
      $wodle_vulnerability_detector_debian_9_disable        = $wazuh::params_manager::wodle_vulnerability_detector_debian_9_disable,
      $wodle_vulnerability_detector_debian_9_update         = $wazuh::params_manager::wodle_vulnerability_detector_debian_9_update,

      # syslog
      $syslog_output                        = $::wazuh::params_manager::syslog_output,
      $syslog_output_level                  = $wazuh::params_manager::syslog_output_level,
      $syslog_output_port                   = $wazuh::params_manager::syslog_output_port,
      $syslog_output_server                 = $wazuh::params_manager::syslog_output_server,
      $syslog_output_format                 = $wazuh::params_manager::syslog_output_format,

      # Authd configuration

      $ossec_auth_disabled                  = $wazuh::params_manager::ossec_auth_disabled,
      $ossec_auth_port                      = $wazuh::params_manager::ossec_auth_port,
      $ossec_auth_use_source_ip             = $wazuh::params_manager::ossec_auth_use_source_ip,
      $ossec_auth_force_insert              = $wazuh::params_manager::ossec_auth_force_insert,
      $ossec_auth_force_time                = $wazuh::params_manager::ossec_auth_force_time,
      $ossec_auth_purgue                    = $wazuh::params_manager::ossec_auth_purgue,
      $ossec_auth_use_password              = $wazuh::params_manager::ossec_auth_use_password,
      $ossec_auth_limit_maxagents           = $wazuh::params_manager::ossec_auth_limit_maxagents,
      $ossec_auth_ciphers                   = $wazuh::params_manager::ossec_auth_ciphers,
      $ossec_auth_ssl_verify_host           = $wazuh::params_manager::ossec_auth_ssl_verify_host,
      $ossec_auth_ssl_manager_cert          = $wazuh::params_manager::ossec_auth_ssl_manager_cert,
      $ossec_auth_ssl_manager_key           = $wazuh::params_manager::ossec_auth_ssl_manager_key,
      $ossec_auth_ssl_auto_negotiate        = $wazuh::params_manager::ossec_auth_ssl_auto_negotiate,


      # syscheck

      $ossec_syscheck_disabled              = $wazuh::params_manager::ossec_syscheck_disabled,
      $ossec_syscheck_frequency             = $wazuh::params_manager::ossec_syscheck_frequency,
      $ossec_syscheck_scan_on_start         = $wazuh::params_manager::ossec_syscheck_scan_on_start,
      $ossec_syscheck_alert_new_files       = $wazuh::params_manager::ossec_syscheck_alert_new_files,
      $ossec_syscheck_auto_ignore           = $wazuh::params_manager::ossec_syscheck_auto_ignore,
      $ossec_syscheck_directories_1         = $wazuh::params_manager::ossec_syscheck_directories_1,
      $ossec_syscheck_directories_2         = $wazuh::params_manager::ossec_syscheck_directories_2,
      $ossec_syscheck_ignore_list           = $wazuh::params_manager::ossec_syscheck_ignore_list,

      $ossec_syscheck_ignore_type_1         = $wazuh::params_manager::ossec_syscheck_ignore_type_1,
      $ossec_syscheck_ignore_type_2         = $wazuh::params_manager::ossec_syscheck_ignore_type_2,

      $ossec_syscheck_nodiff                = $wazuh::params_manager::ossec_syscheck_nodiff,
      $ossec_syscheck_skip_nfs              = $wazuh::params_manager::ossec_syscheck_skip_nfs,

      # Cluster

      $ossec_cluster_name                   = $wazuh::params_manager::ossec_cluster_name,
      $ossec_cluster_node_name              = $wazuh::params_manager::ossec_cluster_node_name,
      $ossec_cluster_node_type              = $wazuh::params_manager::ossec_cluster_node_type,
      $ossec_cluster_key                    = $wazuh::params_manager::ossec_cluster_key,
      $ossec_cluster_port                   = $wazuh::params_manager::ossec_cluster_port,
      $ossec_cluster_bind_addr              = $wazuh::params_manager::ossec_cluster_bind_addr,
      $ossec_cluster_nodes                  = $wazuh::params_manager::ossec_cluster_nodes,
      $ossec_cluster_hidden                 = $wazuh::params_manager::ossec_cluster_hidden,
      $ossec_cluster_disabled               = $wazuh::params_manager::ossec_cluster_disabled,

      #----- End of ossec.conf parameters -------

      $ossec_cluster_enable_firewall        = $wazuh::params_manager::ossec_cluster_enable_firewall,

      $ossec_prefilter                      = $wazuh::params_manager::ossec_prefilter,
      $ossec_integratord_enabled            = $wazuh::params_manager::ossec_integratord_enabled,

      $manage_client_keys                   = $wazuh::params_manager::manage_client_keys,
      $agent_auth_password                  = $wazuh::params_manager::agent_auth_password,
      $ar_repeated_offenders                = $wazuh::params_manager::ar_repeated_offenders,

      $local_decoder_template               = $wazuh::params_manager::local_decoder_template,
      $decoder_exclude                      = $wazuh::params_manager::decoder_exclude,
      $local_rules_template                 = $wazuh::params_manager::local_rules_template,
      $rule_exclude                         = $wazuh::params_manager::rule_exclude,
      $shared_agent_template                = $wazuh::params_manager::shared_agent_template,

      $wazuh_manager_verify_manager_ssl     = $wazuh::params_manager::wazuh_manager_verify_manager_ssl,
      $wazuh_manager_server_crt             = $wazuh::params_manager::wazuh_manager_server_crt,
      $wazuh_manager_server_key             = $wazuh::params_manager::wazuh_manager_server_key,

      $ossec_local_files                    = $::wazuh::params_manager::default_local_files,
) inherits wazuh::params_manager {
  validate_bool(
    $manage_repos, $syslog_output,$wazuh_manager_verify_manager_ssl
  )
  validate_array(
    $decoder_exclude, $rule_exclude
  )

  ## Fail if host is Windows
  if $::osfamily == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  if ($ossec_emailnotification == true) {
    if $ossec_smtp_server == undef {
      fail('$ossec_emailnotification is enabled but $smtp_server was not set')
    }
    validate_string($ossec_smtp_server)
    validate_string($ossec_emailfrom)
    validate_array($ossec_emailto)
  }

  ## Install wazuh-repository
  #if $manage_repos {
  #  # TODO: Allow filtering of EPEL requirement
  #  class { 'wazuh::repo':}
  #  if $::osfamily == 'Debian' {
  #    Class['wazuh::repo'] -> Class['apt::update'] -> Package[$wazuh::params_manager::server_package]
  #  } else {
  #    Class['wazuh::repo'] -> Package[$wazuh::params_manager::server_package]
  #  }
  #}

  # Install and configure Wazuh-manager package

  package { $wazuh::params_manager::server_package:
    ensure  => $server_package_version, # lint:ignore:security_package_pinned_version
  }

  file {
    default:
      owner   => $wazuh::params_manager::config_owner,
      group   => $wazuh::params_manager::config_group,
      mode    => $wazuh::params_manager::config_mode,
      notify  => Service[$wazuh::params_manager::server_service],
      require => Package[$wazuh::params_manager::server_package];
    $wazuh::params_manager::shared_agent_config_file:
      validate_cmd => $wazuh::params_manager::validate_cmd_conf,
      content      => template($shared_agent_template);
    '/var/ossec/etc/rules/local_rules.xml':
      content      => template($local_rules_template);
    '/var/ossec/etc/decoders/local_decoder.xml':
      content      => template($local_decoder_template);
    $wazuh::params_manager::processlist_file:
      content      => template('wazuh/process_list.erb');
  }

  service { $wazuh::params_manager::server_service:
    ensure    => running,
    enable    => true,
    hasstatus => $wazuh::params_manager::service_has_status,
    pattern   => $wazuh::params_manager::server_service,
    provider  => $wazuh::params_manager::ossec_service_provider,
    require   => Package[$wazuh::params_manager::server_package],
  }

  concat { 'ossec.conf':
    path    => $wazuh::params_manager::config_file,
    owner   => $wazuh::params_manager::config_owner,
    group   => $wazuh::params_manager::config_group,
    mode    => $wazuh::params_manager::config_mode,
    require => Package[$wazuh::params_manager::server_package],
    notify  => Service[$wazuh::params_manager::server_service],
  }
  concat::fragment {
    'ossec.conf_header':
      target  => 'ossec.conf',
      order   => 00,
      content => "<ossec_config>\n";
    'ossec.conf_main':
      target  => 'ossec.conf',
      order   => 01,
      content => template($ossec_manager_template);
  }
  if($configure_rootcheck == true){
    concat::fragment {
        'ossec.conf_rootcheck':
          order   => 10,
          target  => 'ossec.conf',
          content => template($ossec_rootcheck_template);
      }
  }
  if ($configure_wodle_openscap == true){
    concat::fragment {
      'ossec.conf_wodle_openscap':
        order   => 15,
        target  => 'ossec.conf',
        content => template($ossec_wodle_openscap_template);
    }
  }
  if ($configure_wodle_cis_cat == true){
    concat::fragment {
      'ossec.conf_wodle_ciscat':
        order   => 20,
        target  => 'ossec.conf',
        content => template($ossec_wodle_cis_cat_template);
    }
  }
  if ($configure_wodle_osquery== true){
    concat::fragment {
      'ossec.conf_wodle_osquery':
        order   => 25,
        target  => 'ossec.conf',
        content => template($ossec_wodle_osquery_template);
    }
  }
  if ($configure_wodle_syscollector == true){
    concat::fragment {
      'ossec.conf_wodle_syscollector':
        order   => 30,
        target  => 'ossec.conf',
        content => template($ossec_wodle_syscollector_template);
    }
  }
  if ($configure_sca == true){
    concat::fragment {
      'ossec.conf_sca':
        order   => 40,
        target  => 'ossec.conf',
        content => template($ossec_sca_template);
      }
  }
  if($configure_vulnerability_detector == true){
    concat::fragment {
      'ossec.conf_wodle_vulnerability_detector':
        order   => 45,
        target  => 'ossec.conf',
        content => template($ossec_wodle_vulnerability_detector_template);
    }
  }
  if($configure_syscheck == true){
    concat::fragment {
      'ossec.conf_syscheck':
        order   => 55,
        target  => 'ossec.conf',
        content => template($ossec_syscheck_template);
    }
  }
  if ($configure_command == true){
    concat::fragment {
          'ossec.conf_command':
            order   => 60,
            target  => 'ossec.conf',
            content => template($ossec_default_commands_template);
      }
  }
  if ($configure_localfile == true){
    concat::fragment {
      'ossec.conf_localfile':
        order   => 65,
        target  => 'ossec.conf',
        content => template($ossec_localfile_template);
    }
  }
  if($configure_ruleset == true){
    concat::fragment {
        'ossec.conf_ruleset':
          order   => 75,
          target  => 'ossec.conf',
          content => template($ossec_ruleset_template);
      }
  }
  if ($configure_auth == true){
    concat::fragment {
        'ossec.conf_auth':
          order   => 80,
          target  => 'ossec.conf',
          content => template($ossec_auth_template);
      }
  }
  if ($configure_cluster == true){
    concat::fragment {
        'ossec.conf_cluster':
          order   => 85,
          target  => 'ossec.conf',
          content => template($ossec_cluster_template);
      }
  }
  if ($configure_active_response == true){
    concat::fragment {
        'ossec.conf_active_response':
          order   => 90,
          target  => 'ossec.conf',
          content => template($ossec_active_response_template);
      }
  }
  concat::fragment {
    'ossec.conf_footer':
      target  => 'ossec.conf',
      order   => 99,
      content => "</ossec_config>\n";
  }

  if ( $manage_client_keys == 'yes') {
    # TODO: ensure the authd service is started if manage_client_keys == authd
    # (see https://github.com/wazuh/wazuh/issues/80)

    file { $wazuh::params_manager::authd_pass_file:
      owner   => $wazuh::params_manager::keys_owner,
      group   => $wazuh::params_manager::keys_group,
      mode    => $wazuh::params_manager::keys_mode,
      content => $agent_auth_password,
      require => Package[$wazuh::params_manager::server_package],
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
        require => Package[$wazuh::params_manager::server_package],
        notify  => Service[$wazuh::params_manager::server_service],
      }

      file { '/var/ossec/etc/sslmanager.cert':
        content => $wazuh_manager_server_crt,
        owner   => 'root',
        group   => 'ossec',
        mode    => '0640',
        require => Package[$wazuh::params_manager::server_package],
        notify  => Service[$wazuh::params_manager::server_service],
      }
    }
  }

  # Manage firewall
  if $manage_firewall == true {
    include firewall
    firewall { '1514 wazuh-manager':
      dport  => $ossec_remote_port,
      proto  => $ossec_remote_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED'],
    }
  }
  if $ossec_cluster_enable_firewall == 'yes'{
    include firewall
    firewall { '1516 wazuh-manager':
      dport  => $ossec_cluster_port,
      proto  => $ossec_remote_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED'],
    }
  }
}
