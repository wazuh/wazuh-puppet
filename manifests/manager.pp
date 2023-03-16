# Copyright (C) 2015, Wazuh Inc.
# Main ossec server config
class wazuh::manager (

    # Installation

      $server_package_version           = $wazuh::params_manager::server_package_version,
      $manage_repos                     = $::wazuh::params_manager::manage_repos,
      $manage_firewall                  = $wazuh::params_manager::manage_firewall,


    ### Ossec.conf blocks

      ## Global

      $ossec_logall                     = $wazuh::params_manager::ossec_logall,
      $ossec_logall_json                = $wazuh::params_manager::ossec_logall_json,
      $ossec_emailnotification          = $wazuh::params_manager::ossec_emailnotification,
      $ossec_emailto                    = $wazuh::params_manager::ossec_emailto,
      $ossec_smtp_server                = $wazuh::params_manager::ossec_smtp_server,
      $ossec_emailfrom                  = $wazuh::params_manager::ossec_emailfrom,
      $ossec_email_maxperhour           = $wazuh::params_manager::ossec_email_maxperhour,
      $ossec_email_log_source           = $wazuh::params_manager::ossec_email_log_source,
      $ossec_email_idsname              = $wazuh::params_manager::ossec_email_idsname,
      $ossec_white_list                 = $wazuh::params_manager::ossec_white_list,
      $ossec_alert_level                = $wazuh::params_manager::ossec_alert_level,
      $ossec_email_alert_level          = $wazuh::params_manager::ossec_email_alert_level,
      $ossec_remote_connection          = $wazuh::params_manager::ossec_remote_connection,
      $ossec_remote_port                = $wazuh::params_manager::ossec_remote_port,
      $ossec_remote_protocol            = $wazuh::params_manager::ossec_remote_protocol,
      $ossec_remote_local_ip            = $wazuh::params_manager::ossec_remote_local_ip,
      $ossec_remote_allowed_ips         = $wazuh::params_manager::ossec_remote_allowed_ips,
      $ossec_remote_queue_size          = $wazuh::params_manager::ossec_remote_queue_size,

      # ossec.conf generation parameters

      $configure_rootcheck                  = $wazuh::params_manager::configure_rootcheck,
      $configure_wodle_openscap             = $wazuh::params_manager::configure_wodle_openscap,
      $configure_wodle_cis_cat              = $wazuh::params_manager::configure_wodle_cis_cat,
      $configure_wodle_osquery              = $wazuh::params_manager::configure_wodle_osquery,
      $configure_wodle_syscollector         = $wazuh::params_manager::configure_wodle_syscollector,
      $configure_wodle_docker_listener      = $wazuh::params_manager::configure_wodle_docker_listener,
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
      $ossec_wodle_docker_listener_template         = $wazuh::params_manager::ossec_wodle_docker_listener_template,
      $ossec_vulnerability_detector_template        = $wazuh::params_manager::ossec_vulnerability_detector_template,
      $ossec_sca_template                           = $wazuh::params_manager::ossec_sca_template,
      $ossec_syscheck_template                      = $wazuh::params_manager::ossec_syscheck_template,
      $ossec_default_commands_template              = $wazuh::params_manager::ossec_default_commands_template,
      $ossec_localfile_template                     = $wazuh::params_manager::ossec_localfile_template,
      $ossec_ruleset_template                       = $wazuh::params_manager::ossec_ruleset_template,
      $ossec_auth_template                          = $wazuh::params_manager::ossec_auth_template,
      $ossec_cluster_template                       = $wazuh::params_manager::ossec_cluster_template,
      $ossec_active_response_template               = $wazuh::params_manager::ossec_active_response_template,
      $ossec_syslog_output_template                 = $wazuh::params_manager::ossec_syslog_output_template,

      # active-response
      $ossec_active_response_command                =  $wazuh::params_manager::active_response_command,
      $ossec_active_response_location               =  $wazuh::params_manager::active_response_location,
      $ossec_active_response_level                  =  $wazuh::params_manager::active_response_level,
      $ossec_active_response_agent_id               =  $wazuh::params_manager::active_response_agent_id,
      $ossec_active_response_rules_id               =  $wazuh::params_manager::active_response_rules_id,
      $ossec_active_response_timeout                =  $wazuh::params_manager::active_response_timeout,
      $ossec_active_response_repeated_offenders     =  $wazuh::params_manager::active_response_repeated_offenders,


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
      $ossec_rootcheck_ignore_list          = $wazuh::params_manager::ossec_rootcheck_ignore_list,
      $ossec_rootcheck_ignore_sregex_list   = $wazuh::params_manager::ossec_rootcheck_ignore_sregex_list,
      $ossec_rootcheck_rootkit_files        = $wazuh::params_manager::ossec_rootcheck_rootkit_files,
      $ossec_rootcheck_rootkit_trojans      = $wazuh::params_manager::ossec_rootcheck_rootkit_trojans,
      $ossec_rootcheck_skip_nfs             = $wazuh::params_manager::ossec_rootcheck_skip_nfs,
      $ossec_rootcheck_system_audit         = $wazuh::params_manager::ossec_rootcheck_system_audit,

      # SCA

      ## Amazon
      $sca_amazon_enabled = $wazuh::params_manager::sca_amazon_enabled,
      $sca_amazon_scan_on_start = $wazuh::params_manager::sca_amazon_scan_on_start,
      $sca_amazon_interval = $wazuh::params_manager::sca_amazon_interval,
      $sca_amazon_skip_nfs = $wazuh::params_manager::sca_amazon_skip_nfs,
      $sca_amazon_policies = $wazuh::params_manager::sca_amazon_policies,

      ## RHEL
      $sca_rhel_enabled = $wazuh::params_manager::sca_rhel_enabled,
      $sca_rhel_scan_on_start = $wazuh::params_manager::sca_rhel_scan_on_start,
      $sca_rhel_interval = $wazuh::params_manager::sca_rhel_interval,
      $sca_rhel_skip_nfs = $wazuh::params_manager::sca_rhel_skip_nfs,
      $sca_rhel_policies = $wazuh::params_manager::sca_rhel_policies,

      ## <Linux else>
      $sca_else_enabled = $wazuh::params_manager::sca_else_enabled,
      $sca_else_scan_on_start = $wazuh::params_manager::sca_else_scan_on_start,
      $sca_else_interval = $wazuh::params_manager::sca_else_interval,
      $sca_else_skip_nfs = $wazuh::params_manager::sca_else_skip_nfs,
      $sca_else_policies = $wazuh::params_manager::sca_else_policies,


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

      #docker-listener
      $wodle_docker_listener_disabled       = $wazuh::params_manager::wodle_docker_listener_disabled,

      #vulnerability-detector
      $vulnerability_detector_enabled                            = $wazuh::params_manager::vulnerability_detector_enabled,
      $vulnerability_detector_interval                           = $wazuh::params_manager::vulnerability_detector_interval,
      $vulnerability_detector_min_full_scan_interval             = $wazuh::params_manager::vulnerability_detector_min_full_scan_interval,
      $vulnerability_detector_run_on_start                       = $wazuh::params_manager::vulnerability_detector_run_on_start,
# lint:ignore:140chars
      $vulnerability_detector_provider_canonical                 = $wazuh::params_manager::vulnerability_detector_provider_canonical,
      $vulnerability_detector_provider_canonical_enabled         = $wazuh::params_manager::vulnerability_detector_provider_canonical_enabled,
      $vulnerability_detector_provider_canonical_os              = $wazuh::params_manager::vulnerability_detector_provider_canonical_os,
      $vulnerability_detector_provider_canonical_update_interval = $wazuh::params_manager::vulnerability_detector_provider_canonical_update_interval,

      $vulnerability_detector_provider_debian                    = $wazuh::params_manager::vulnerability_detector_provider_debian,
      $vulnerability_detector_provider_debian_enabled            = $wazuh::params_manager::vulnerability_detector_provider_debian_enabled,
      $vulnerability_detector_provider_debian_os                 = $wazuh::params_manager::vulnerability_detector_provider_debian_os,
      $vulnerability_detector_provider_debian_update_interval    = $wazuh::params_manager::vulnerability_detector_provider_debian_update_interval,

      $vulnerability_detector_provider_redhat                    = $wazuh::params_manager::vulnerability_detector_provider_redhat,
      $vulnerability_detector_provider_redhat_enabled            = $wazuh::params_manager::vulnerability_detector_provider_redhat_enabled,
      $vulnerability_detector_provider_redhat_os                 = $wazuh::params_manager::vulnerability_detector_provider_redhat_os,
      $vulnerability_detector_provider_redhat_update_from_year   = $wazuh::params_manager::vulnerability_detector_provider_redhat_update_from_year,
      $vulnerability_detector_provider_redhat_update_interval    = $wazuh::params_manager::vulnerability_detector_provider_redhat_update_interval,

      $vulnerability_detector_provider_nvd                       = $wazuh::params_manager::vulnerability_detector_provider_nvd,
      $vulnerability_detector_provider_nvd_enabled               = $wazuh::params_manager::vulnerability_detector_provider_nvd_enabled,
      $vulnerability_detector_provider_nvd_os                    = $wazuh::params_manager::vulnerability_detector_provider_nvd_os,
      $vulnerability_detector_provider_nvd_update_from_year      = $wazuh::params_manager::vulnerability_detector_provider_nvd_update_from_year,
      $vulnerability_detector_provider_nvd_update_interval       = $wazuh::params_manager::vulnerability_detector_provider_nvd_update_interval,
      #lint:endignore

      $vulnerability_detector_provider_arch                   = $wazuh::params_manager::vulnerability_detector_provider_arch,
      $vulnerability_detector_provider_arch_enabled           = $wazuh::params_manager::vulnerability_detector_provider_arch_enabled,
      $vulnerability_detector_provider_arch_update_interval   = $wazuh::params_manager::vulnerability_detector_provider_arch_update_interval,

      $vulnerability_detector_provider_alas                   = $wazuh::params_manager::vulnerability_detector_provider_alas,
      $vulnerability_detector_provider_alas_enabled           = $wazuh::params_manager::vulnerability_detector_provider_alas_enabled,
      $vulnerability_detector_provider_alas_os              = $wazuh::params_manager::vulnerability_detector_provider_alas_os,
      $vulnerability_detector_provider_alas_update_interval   = $wazuh::params_manager::vulnerability_detector_provider_alas_update_interval,

      $vulnerability_detector_provider_msu                   = $wazuh::params_manager::vulnerability_detector_provider_msu,
      $vulnerability_detector_provider_msu_enabled           = $wazuh::params_manager::vulnerability_detector_provider_msu_enabled,
      $vulnerability_detector_provider_msu_update_interval   = $wazuh::params_manager::vulnerability_detector_provider_msu_update_interval,


      # syslog
      $syslog_output                        = $wazuh::params_manager::syslog_output,
      $syslog_output_level                  = $wazuh::params_manager::syslog_output_level,
      $syslog_output_port                   = $wazuh::params_manager::syslog_output_port,
      $syslog_output_server                 = $wazuh::params_manager::syslog_output_server,
      $syslog_output_format                 = $wazuh::params_manager::syslog_output_format,

      # Authd configuration
      $ossec_auth_disabled                  = $wazuh::params_manager::ossec_auth_disabled,
      $ossec_auth_port                      = $wazuh::params_manager::ossec_auth_port,
      $ossec_auth_use_source_ip             = $wazuh::params_manager::ossec_auth_use_source_ip,
      $ossec_auth_force_enabled             = $wazuh::params_manager::ossec_auth_force_enabled,
      $ossec_auth_force_key_mismatch        = $wazuh::params_manager::ossec_auth_force_key_mismatch,
      $ossec_auth_force_disc_time           = $wazuh::params_manager::ossec_auth_force_disc_time,
      $ossec_auth_force_after_reg_time      = $wazuh::params_manager::ossec_auth_force_after_reg_time,
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
      $ossec_syscheck_auto_ignore           = $wazuh::params_manager::ossec_syscheck_auto_ignore,
      $ossec_syscheck_directories_1         = $wazuh::params_manager::ossec_syscheck_directories_1,
      $ossec_syscheck_directories_2         = $wazuh::params_manager::ossec_syscheck_directories_2,
      $ossec_syscheck_whodata_directories_1            = $wazuh::params_manager::ossec_syscheck_whodata_directories_1,
      $ossec_syscheck_realtime_directories_1           = $wazuh::params_manager::ossec_syscheck_realtime_directories_1,
      $ossec_syscheck_whodata_directories_2            = $wazuh::params_manager::ossec_syscheck_whodata_directories_2,
      $ossec_syscheck_realtime_directories_2           = $wazuh::params_manager::ossec_syscheck_realtime_directories_2,
      $ossec_syscheck_ignore_list           = $wazuh::params_manager::ossec_syscheck_ignore_list,

      $ossec_syscheck_ignore_type_1         = $wazuh::params_manager::ossec_syscheck_ignore_type_1,
      $ossec_syscheck_ignore_type_2         = $wazuh::params_manager::ossec_syscheck_ignore_type_2,
      $ossec_syscheck_process_priority             = $wazuh::params_manager::ossec_syscheck_process_priority,
      $ossec_syscheck_synchronization_enabled      = $wazuh::params_manager::ossec_syscheck_synchronization_enabled,
      $ossec_syscheck_synchronization_interval     = $wazuh::params_manager::ossec_syscheck_synchronization_interval,
      $ossec_syscheck_synchronization_max_eps      = $wazuh::params_manager::ossec_syscheck_synchronization_max_eps,
      $ossec_syscheck_synchronization_max_interval = $wazuh::params_manager::ossec_syscheck_synchronization_max_interval,

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

      # API


      $wazuh_api_host                           = $wazuh::params_manager::wazuh_api_host,

      $wazuh_api_port                           = $wazuh::params_manager::wazuh_api_port,
      $wazuh_api_file                           = $wazuh::params_manager::wazuh_api_file,

      $wazuh_api_https_enabled                  = $wazuh::params_manager::wazuh_api_https_enabled,
      $wazuh_api_https_key                      = $wazuh::params_manager::wazuh_api_https_key,

      $wazuh_api_https_cert                     = $wazuh::params_manager::wazuh_api_https_cert,
      $wazuh_api_https_use_ca                   = $wazuh::params_manager::wazuh_api_https_use_ca,
      $wazuh_api_https_ca                       = $wazuh::params_manager::wazuh_api_https_ca,
      $wazuh_api_logs_level                     = $wazuh::params_manager::wazuh_api_logs_level,
      $wazuh_api_logs_format                    = $wazuh::params_manager::wazuh_api_logs_format,
      $wazuh_api_ssl_ciphers                    = $wazuh::params_manager::wazuh_api_ssl_ciphers,
      $wazuh_api_ssl_protocol                   = $wazuh::params_manager::wazuh_api_ssl_protocol,

      $wazuh_api_cors_enabled                   = $wazuh::params_manager::wazuh_api_cors_enabled,
      $wazuh_api_cors_source_route              = $wazuh::params_manager::wazuh_api_cors_source_route,
      $wazuh_api_cors_expose_headers            = $wazuh::params_manager::wazuh_api_cors_expose_headers,


      $wazuh_api_cors_allow_credentials         = $::wazuh::params_manager::wazuh_api_cors_allow_credentials,
      $wazuh_api_cache_enabled                  = $::wazuh::params_manager::wazuh_api_cache_enabled,

      $wazuh_api_cache_time                     = $::wazuh::params_manager::wazuh_api_cache_time,

      $wazuh_api_access_max_login_attempts      = $::wazuh::params_manager::wazuh_api_access_max_login_attempts,
      $wazuh_api_access_block_time              = $::wazuh::params_manager::wazuh_api_access_block_time,
      $wazuh_api_access_max_request_per_minute  = $::wazuh::params_manager::wazuh_api_access_max_request_per_minute,
      $wazuh_api_drop_privileges                = $::wazuh::params_manager::wazuh_api_drop_privileges,
      $wazuh_api_experimental_features          = $::wazuh::params_manager::wazuh_api_experimental_features,

      $remote_commands_localfile                = $::wazuh::params_manager::remote_commands_localfile,
      $remote_commands_localfile_exceptions     = $::wazuh::params_manager::remote_commands_localfile_exceptions,
      $remote_commands_wodle                    = $::wazuh::params_manager::remote_commands_wodle,
      $remote_commands_wodle_exceptions         = $::wazuh::params_manager::remote_commands_wodle_exceptions,
      $limits_eps                               = $::wazuh::params_manager::limits_eps,

      $wazuh_api_template                       = $::wazuh::params_manager::wazuh_api_template,




) inherits wazuh::params_manager {
  validate_legacy(
    Boolean, 'validate_bool', $manage_repos, $syslog_output,$wazuh_manager_verify_manager_ssl
  )
  validate_legacy(
    Array, 'validate_array', $decoder_exclude, $rule_exclude
  )

  ## Determine which kernel and family puppet is running on. Will be used on _localfile, _rootcheck, _syscheck & _sca

  if ($::kernel == 'windows') {
    $kernel = 'Linux'

  }else{
    $kernel = 'Linux'
    if ($::osfamily == 'Debian'){
      $os_family = 'debian'
    }else{
      $os_family = 'centos'
    }
  }


  if ( $ossec_syscheck_whodata_directories_1 == 'yes' ) or ( $ossec_syscheck_whodata_directories_2 == 'yes' ) {
    case $::operatingsystem {
      'Debian', 'debian', 'Ubuntu', 'ubuntu': {
        package { 'Installing Auditd...':
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
  }

  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  validate_legacy(Boolean, 'validate_bool', $ossec_emailnotification)
  if ($ossec_emailnotification) {
    if $ossec_smtp_server == undef {
      fail('$ossec_emailnotification is enabled but $smtp_server was not set')
    }
    validate_legacy(String, 'validate_string', $ossec_smtp_server)
    validate_legacy(String, 'validate_string', $ossec_emailfrom)
    validate_legacy(Array, 'validate_array', $ossec_emailto)
  }

  if $::osfamily == 'windows' {
    fail('The ossec module does not yet support installing the OSSEC HIDS server on Windows')
  }

  # Install wazuh-repository

  if $manage_repos {
    # TODO: Allow filtering of EPEL requirement
    class { 'wazuh::repo':}
    if $::osfamily == 'Debian' {
      Class['wazuh::repo'] -> Class['apt::update'] -> Package[$wazuh::params_manager::server_package]
    } else {
      Class['wazuh::repo'] -> Package[$wazuh::params_manager::server_package]
    }
  }
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

  ## Declaring variables for localfile and wodles generation

  case $::operatingsystem{
    'RedHat', 'OracleLinux':{
      $apply_template_os = 'rhel'
      if ( $::operatingsystemrelease =~ /^9.*/ ){
        $rhel_version = '9'
      }elsif ( $::operatingsystemrelease =~ /^8.*/ ){
        $rhel_version = '8'
      }elsif ( $::operatingsystemrelease =~ /^7.*/ ){
        $rhel_version = '7'
      }elsif ( $::operatingsystemrelease =~ /^6.*/ ){
        $rhel_version = '6'
      }elsif ( $::operatingsystemrelease =~ /^5.*/ ){
        $rhel_version = '5'
      }else{
        fail('This ossec module has not been tested on your distribution')
      }
    }'Debian', 'debian', 'Ubuntu', 'ubuntu':{
      $apply_template_os = 'debian'
      if ( $::lsbdistcodename == 'wheezy') or ($::lsbdistcodename == 'jessie'){
        $debian_additional_templates = 'yes'
      }
    }'Amazon':{
      $apply_template_os = 'amazon'
    }'CentOS','Centos','centos':{
      $apply_template_os = 'centos'
    }
    default: { fail('This ossec module has not been tested on your distribution') }
  }



  concat { 'manager_ossec.conf':
    path    => $wazuh::params_manager::config_file,
    owner   => $wazuh::params_manager::config_owner,
    group   => $wazuh::params_manager::config_group,
    mode    => $wazuh::params_manager::config_mode,
    require => Package[$wazuh::params_manager::server_package],
    notify  => Service[$wazuh::params_manager::server_service],
  }
  concat::fragment {
    'ossec.conf_header':
      target  => 'manager_ossec.conf',
      order   => 00,
      content => "<ossec_config>\n";
    'ossec.conf_main':
      target  => 'manager_ossec.conf',
      order   => 01,
      content => template($ossec_manager_template);
  }

  if ($syslog_output == true){
    concat::fragment {
      'ossec.conf_syslog_output':
        target  => 'manager_ossec.conf',
        content => template($ossec_syslog_output_template);
    }
  }

  if($configure_rootcheck == true){
    concat::fragment {
        'ossec.conf_rootcheck':
          order   => 10,
          target  => 'manager_ossec.conf',
          content => template($ossec_rootcheck_template);
      }
  }

  if ($configure_wodle_openscap == true){
    concat::fragment {
      'ossec.conf_wodle_openscap':
        order   => 15,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_openscap_template);
    }
  }
  if ($configure_wodle_cis_cat == true){
    concat::fragment {
      'ossec.conf_wodle_ciscat':
        order   => 20,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_cis_cat_template);
    }
  }
  if ($configure_wodle_osquery== true){
    concat::fragment {
      'ossec.conf_wodle_osquery':
        order   => 25,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_osquery_template);
    }
  }
  if ($configure_wodle_syscollector == true){
    concat::fragment {
      'ossec.conf_wodle_syscollector':
        order   => 30,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_syscollector_template);
    }
  }
  if ($configure_wodle_docker_listener == true){
    concat::fragment {
      'ossec.conf_wodle_docker_listener':
        order   => 30,
        target  => 'manager_ossec.conf',
        content => template($ossec_wodle_docker_listener_template);
    }
  }
  if ($configure_sca == true){
    concat::fragment {
      'ossec.conf_sca':
        order   => 40,
        target  => 'manager_ossec.conf',
        content => template($ossec_sca_template);
      }
  }
  if($configure_vulnerability_detector == true){
    concat::fragment {
      'ossec.conf_vulnerability_detector':
        order   => 45,
        target  => 'manager_ossec.conf',
        content => template($ossec_vulnerability_detector_template);
    }
  }
  if($configure_syscheck == true){
    concat::fragment {
      'ossec.conf_syscheck':
        order   => 55,
        target  => 'manager_ossec.conf',
        content => template($ossec_syscheck_template);
    }
  }
  if ($configure_command == true){
    concat::fragment {
          'ossec.conf_command':
            order   => 60,
            target  => 'manager_ossec.conf',
            content => template($ossec_default_commands_template);
      }
  }
  if ($configure_localfile == true){
    concat::fragment {
      'ossec.conf_localfile':
        order   => 65,
        target  => 'manager_ossec.conf',
        content => template($ossec_localfile_template);
    }
  }
  if($configure_ruleset == true){
    concat::fragment {
        'ossec.conf_ruleset':
          order   => 75,
          target  => 'manager_ossec.conf',
          content => template($ossec_ruleset_template);
      }
  }
  if ($configure_auth == true){
    concat::fragment {
        'ossec.conf_auth':
          order   => 80,
          target  => 'manager_ossec.conf',
          content => template($ossec_auth_template);
      }
  }
  if ($configure_cluster == true){
    concat::fragment {
        'ossec.conf_cluster':
          order   => 85,
          target  => 'manager_ossec.conf',
          content => template($ossec_cluster_template);
      }
  }
  if ($configure_active_response == true){
    wazuh::activeresponse { 'active-response configuration':
      active_response_command            => $ossec_active_response_command,
      active_response_location           => $ossec_active_response_location,
      active_response_level              => $ossec_active_response_level,
      active_response_agent_id           => $ossec_active_response_agent_id,
      active_response_rules_id           => $ossec_active_response_rules_id,
      active_response_timeout            => $ossec_active_response_timeout,
      active_response_repeated_offenders => $ossec_active_response_repeated_offenders,
      order_arg                          => 90
    }
  }
  concat::fragment {
    'ossec.conf_footer':
      target  => 'manager_ossec.conf',
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
      notify  => Service[$wazuh::params_manager::server_service],
    }
  }

  # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl
  if $wazuh_manager_verify_manager_ssl {

    if ($wazuh_manager_server_crt != undef) and ($wazuh_manager_server_key != undef) {
      validate_legacy(
        String, 'validate_string', $wazuh_manager_server_crt, $wazuh_manager_server_key
      )

      file { '/var/ossec/etc/sslmanager.key':
        content => $wazuh_manager_server_key,
        owner   => 'root',
        group   => 'wazuh',
        mode    => '0640',
        require => Package[$wazuh::params_manager::server_package],
        notify  => Service[$wazuh::params_manager::server_service],
      }

      file { '/var/ossec/etc/sslmanager.cert':
        content => $wazuh_manager_server_crt,
        owner   => 'root',
        group   => 'wazuh',
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

  if ( $ossec_syscheck_whodata_directories_1 == 'yes' ) or ( $ossec_syscheck_whodata_directories_2 == 'yes' ) {
    exec { 'Ensure wazuh-fim rule is added to auditctl':
      command => '/sbin/auditctl -l',
      unless  => '/sbin/auditctl -l | grep wazuh_fim',
      tries   => 2
    }
  }

  file { '/var/ossec/api/configuration/api.yaml':
    owner   => 'root',
    group   => 'wazuh',
    mode    => '0640',
    content => template('wazuh/wazuh_api_yml.erb'),
    require => Package[$wazuh::params_manager::server_package],
    notify  => Service[$wazuh::params_manager::server_service]
  }

}
