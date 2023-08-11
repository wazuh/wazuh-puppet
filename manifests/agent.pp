# Copyright (C) 2015, Wazuh Inc.

# Puppet class that installs and manages the Wazuh agent
class wazuh::agent (

  # Versioning and package names

  $agent_package_version             = $wazuh::params_agent::agent_package_version,
  $agent_package_revision            = $wazuh::params_agent::agent_package_revision,
  $agent_package_name                = $wazuh::params_agent::agent_package_name,
  $agent_service_name                = $wazuh::params_agent::agent_service_name,
  $agent_service_ensure              = $wazuh::params_agent::agent_service_ensure,
  $agent_msi_download_location       = $wazuh::params_agent::agent_msi_download_location,

  # Manage repository

  $manage_repo                       = $wazuh::params_agent::manage_repo,

  # Authd registration options
  $manage_client_keys                = $wazuh::params_agent::manage_client_keys,
  $agent_name                        = $wazuh::params_agent::agent_name,
  $agent_group                       = $wazuh::params_agent::agent_group,
  $agent_address                     = $wazuh::params_agent::agent_address,
  $wazuh_agent_cert                  = $wazuh::params_agent::wazuh_agent_cert,
  $wazuh_agent_key                   = $wazuh::params_agent::wazuh_agent_key,
  $wazuh_agent_cert_path             = $wazuh::params_agent::wazuh_agent_cert_path,
  $wazuh_agent_key_path              = $wazuh::params_agent::wazuh_agent_key_path,
  $agent_auth_password               = $wazuh::params_agent::agent_auth_password,
  $wazuh_manager_root_ca_pem         = $wazuh::params_agent::wazuh_manager_root_ca_pem,
  $wazuh_manager_root_ca_pem_path    = $wazuh::params_agent::wazuh_manager_root_ca_pem_path,

  ## ossec.conf generation parameters
  # Generation variables
  $configure_rootcheck               = $wazuh::params_agent::configure_rootcheck,
  $configure_wodle_openscap          = $wazuh::params_agent::configure_wodle_openscap,
  $configure_wodle_cis_cat           = $wazuh::params_agent::configure_wodle_cis_cat,
  $configure_wodle_osquery           = $wazuh::params_agent::configure_wodle_osquery,
  $configure_wodle_syscollector      = $wazuh::params_agent::configure_wodle_syscollector,
  $configure_wodle_docker_listener   = $wazuh::params_agent::configure_wodle_docker_listener,
  $configure_sca                     = $wazuh::params_agent::configure_sca,
  $configure_syscheck                = $wazuh::params_agent::configure_syscheck,
  $configure_localfile               = $wazuh::params_agent::configure_localfile,
  $configure_active_response         = $wazuh::params_agent::configure_active_response,
  $configure_labels                  = $wazuh::params_agent::configure_labels,

  # Templates paths
  $ossec_conf_template                  = $wazuh::params_agent::ossec_conf_template,
  $ossec_rootcheck_template             = $wazuh::params_agent::ossec_rootcheck_template,
  $ossec_wodle_openscap_template        = $wazuh::params_agent::ossec_wodle_openscap_template,
  $ossec_wodle_cis_cat_template         = $wazuh::params_agent::ossec_wodle_cis_cat_template,
  $ossec_wodle_osquery_template         = $wazuh::params_agent::ossec_wodle_osquery_template,
  $ossec_wodle_syscollector_template    = $wazuh::params_agent::ossec_wodle_syscollector_template,
  $ossec_wodle_docker_listener_template = $wazuh::params_agent::ossec_wodle_docker_listener_template,
  $ossec_sca_template                   = $wazuh::params_agent::ossec_sca_template,
  $ossec_syscheck_template              = $wazuh::params_agent::ossec_syscheck_template,
  $ossec_localfile_template             = $wazuh::params_agent::ossec_localfile_template,
  $ossec_auth                           = $wazuh::params_agent::ossec_auth,
  $ossec_cluster                        = $wazuh::params_agent::ossec_cluster,
  $ossec_active_response_template       = $wazuh::params_agent::ossec_active_response_template,
  $ossec_labels_template                = $wazuh::params_agent::ossec_labels_template,

  # Server configuration

  $wazuh_register_endpoint           = $wazuh::params_agent::wazuh_register_endpoint,
  $wazuh_reporting_endpoint          = $wazuh::params_agent::wazuh_reporting_endpoint,
  $ossec_port                        = $wazuh::params_agent::ossec_port,
  $ossec_protocol                    = $wazuh::params_agent::ossec_protocol,
  $wazuh_max_retries                 = $wazuh::params_agent::wazuh_max_retries,
  $wazuh_retry_interval              = $wazuh::params_agent::wazuh_retry_interval,
  $ossec_config_ubuntu_profiles      = $wazuh::params_agent::ossec_config_ubuntu_profiles,
  $ossec_config_centos_profiles      = $wazuh::params_agent::ossec_config_centos_profiles,
  $ossec_notify_time                 = $wazuh::params_agent::ossec_notify_time,
  $ossec_time_reconnect              = $wazuh::params_agent::ossec_time_reconnect,
  $ossec_auto_restart                = $wazuh::params_agent::ossec_auto_restart,
  $ossec_crypto_method               = $wazuh::params_agent::ossec_crypto_method,
  $client_buffer_disabled            = $wazuh::params_agent::client_buffer_disabled,
  $client_buffer_queue_size          = $wazuh::params_agent::client_buffer_queue_size,
  $client_buffer_events_per_second   = $wazuh::params_agent::client_buffer_events_per_second,

  # Auto enrollment configuration

  $wazuh_enrollment_enabled          = $wazuh::params_agent::wazuh_enrollment_enabled,
  $wazuh_enrollment_manager_address  = $wazuh::params_agent::wazuh_enrollment_manager_address,
  $wazuh_enrollment_port             = $wazuh::params_agent::wazuh_enrollment_port,
  $wazuh_enrollment_agent_name       = $wazuh::params_agent::wazuh_enrollment_agent_name,
  $wazuh_enrollment_groups           = $wazuh::params_agent::wazuh_enrollment_groups,
  $wazuh_enrollment_agent_address    = $wazuh::params_agent::wazuh_enrollment_agent_address,
  $wazuh_enrollment_ssl_cipher       = $wazuh::params_agent::wazuh_enrollment_ssl_cipher,
  $wazuh_enrollment_server_ca_path   = $wazuh::params_agent::wazuh_enrollment_server_ca_path,
  $wazuh_enrollment_agent_cert_path  = $wazuh::params_agent::wazuh_enrollment_agent_cert_path,
  $wazuh_enrollment_agent_key_path   = $wazuh::params_agent::wazuh_enrollment_agent_key_path,
  $wazuh_enrollment_auth_pass        = $wazuh::params_agent::wazuh_enrollment_auth_pass,
  $wazuh_enrollment_auth_pass_path   = $wazuh::params_agent::wazuh_enrollment_auth_pass_path,
  $wazuh_enrollment_auto_method      = $wazuh::params_agent::wazuh_enrollment_auto_method,
  $wazuh_delay_after_enrollment      = $wazuh::params_agent::wazuh_delay_after_enrollment,
  $wazuh_enrollment_use_source_ip    = $wazuh::params_agent::wazuh_enrollment_use_source_ip,


  # Rootcheck
  $ossec_rootcheck_disabled           = $wazuh::params_agent::ossec_rootcheck_disabled,
  $ossec_rootcheck_check_files        = $wazuh::params_agent::ossec_rootcheck_check_files,
  $ossec_rootcheck_check_trojans      = $wazuh::params_agent::ossec_rootcheck_check_trojans,
  $ossec_rootcheck_check_dev          = $wazuh::params_agent::ossec_rootcheck_check_dev,
  $ossec_rootcheck_check_sys          = $wazuh::params_agent::ossec_rootcheck_check_sys,
  $ossec_rootcheck_check_pids         = $wazuh::params_agent::ossec_rootcheck_check_pids,
  $ossec_rootcheck_check_ports        = $wazuh::params_agent::ossec_rootcheck_check_ports,
  $ossec_rootcheck_check_if           = $wazuh::params_agent::ossec_rootcheck_check_if,
  $ossec_rootcheck_frequency          = $wazuh::params_agent::ossec_rootcheck_frequency,
  $ossec_rootcheck_ignore_list        = $wazuh::params_agent::ossec_rootcheck_ignore_list,
  $ossec_rootcheck_ignore_sregex_list = $wazuh::params_agent::ossec_rootcheck_ignore_sregex_list,
  $ossec_rootcheck_rootkit_files      = $wazuh::params_agent::ossec_rootcheck_rootkit_files,
  $ossec_rootcheck_rootkit_trojans    = $wazuh::params_agent::ossec_rootcheck_rootkit_trojans,
  $ossec_rootcheck_skip_nfs           = $wazuh::params_agent::ossec_rootcheck_skip_nfs,
  $ossec_rootcheck_system_audit      = $wazuh::params_agent::ossec_rootcheck_system_audit,


  # rootcheck windows
  $ossec_rootcheck_windows_disabled        = $wazuh::params_agent::ossec_rootcheck_windows_disabled,
  $ossec_rootcheck_windows_windows_apps    = $wazuh::params_agent::ossec_rootcheck_windows_windows_apps,
  $ossec_rootcheck_windows_windows_malware = $wazuh::params_agent::ossec_rootcheck_windows_windows_malware,

  # SCA

  ## Amazon
  $sca_amazon_enabled = $wazuh::params_agent::sca_amazon_enabled,
  $sca_amazon_scan_on_start = $wazuh::params_agent::sca_amazon_scan_on_start,
  $sca_amazon_interval = $wazuh::params_agent::sca_amazon_interval,
  $sca_amazon_skip_nfs = $wazuh::params_agent::sca_amazon_skip_nfs,
  $sca_amazon_policies = $wazuh::params_agent::sca_amazon_policies,

  ## RHEL
  $sca_rhel_enabled = $wazuh::params_agent::sca_rhel_enabled,
  $sca_rhel_scan_on_start = $wazuh::params_agent::sca_rhel_scan_on_start,
  $sca_rhel_interval = $wazuh::params_agent::sca_rhel_interval,
  $sca_rhel_skip_nfs = $wazuh::params_agent::sca_rhel_skip_nfs,
  $sca_rhel_policies = $wazuh::params_agent::sca_rhel_policies,

  ## <Linux else>
  $sca_else_enabled = $wazuh::params_agent::sca_else_enabled,
  $sca_else_scan_on_start = $wazuh::params_agent::sca_else_scan_on_start,
  $sca_else_interval = $wazuh::params_agent::sca_else_interval,
  $sca_else_skip_nfs = $wazuh::params_agent::sca_else_skip_nfs,
  $sca_else_policies = $wazuh::params_agent::sca_else_policies,

  $sca_windows_enabled = $wazuh::params_agent::sca_windows_enabled,
  $sca_windows_scan_on_start = $wazuh::params_agent::sca_windows_scan_on_start,
  $sca_windows_interval = $wazuh::params_agent::sca_windows_interval,
  $sca_windows_skip_nfs = $wazuh::params_agent::sca_windows_skip_nfs,
  $sca_windows_policies = $wazuh::params_agent::sca_windows_policies,

  ## Wodles

  # Openscap
  $wodle_openscap_disabled           = $wazuh::params_agent::wodle_openscap_disabled,
  $wodle_openscap_timeout            = $wazuh::params_agent::wodle_openscap_timeout,
  $wodle_openscap_interval           = $wazuh::params_agent::wodle_openscap_interval,
  $wodle_openscap_scan_on_start      = $wazuh::params_agent::wodle_openscap_scan_on_start,

  # Ciscat
  $wodle_ciscat_disabled             = $wazuh::params_agent::wodle_ciscat_disabled,
  $wodle_ciscat_timeout              = $wazuh::params_agent::wodle_ciscat_timeout,
  $wodle_ciscat_interval             = $wazuh::params_agent::wodle_ciscat_interval,
  $wodle_ciscat_scan_on_start        = $wazuh::params_agent::wodle_ciscat_scan_on_start,
  $wodle_ciscat_java_path            = $wazuh::params_agent::wodle_ciscat_java_path,
  $wodle_ciscat_ciscat_path          = $wazuh::params_agent::wodle_ciscat_ciscat_path,

  #Osquery

  $wodle_osquery_disabled            = $wazuh::params_agent::wodle_osquery_disabled,
  $wodle_osquery_run_daemon          = $wazuh::params_agent::wodle_osquery_run_daemon,
  $wodle_osquery_bin_path            = $wazuh::params_agent::wodle_osquery_bin_path,
  $wodle_osquery_log_path            = $wazuh::params_agent::wodle_osquery_log_path,
  $wodle_osquery_config_path         = $wazuh::params_agent::wodle_osquery_config_path,
  $wodle_osquery_add_labels          = $wazuh::params_agent::wodle_osquery_add_labels,

  # Syscollector

  $wodle_syscollector_disabled       = $wazuh::params_agent::wodle_syscollector_disabled,
  $wodle_syscollector_interval       = $wazuh::params_agent::wodle_syscollector_interval,
  $wodle_syscollector_scan_on_start  = $wazuh::params_agent::wodle_syscollector_scan_on_start,
  $wodle_syscollector_hardware       = $wazuh::params_agent::wodle_syscollector_hardware,
  $wodle_syscollector_os             = $wazuh::params_agent::wodle_syscollector_os,
  $wodle_syscollector_network        = $wazuh::params_agent::wodle_syscollector_network,
  $wodle_syscollector_packages       = $wazuh::params_agent::wodle_syscollector_packages,
  $wodle_syscollector_ports          = $wazuh::params_agent::wodle_syscollector_ports,
  $wodle_syscollector_processes      = $wazuh::params_agent::wodle_syscollector_processes,
  $wodle_syscollector_hotfixes       = $wazuh::params_agent::wodle_syscollector_hotfixes,

  # Docker-listener
  $wodle_docker_listener_disabled    = $wazuh::params_agent::wodle_docker_listener_disabled,

  # Localfile
  $ossec_local_files                 = $wazuh::params_agent::default_local_files,

  # Syscheck
  $ossec_syscheck_disabled           = $wazuh::params_agent::ossec_syscheck_disabled,
  $ossec_syscheck_frequency          = $wazuh::params_agent::ossec_syscheck_frequency,
  $ossec_syscheck_scan_on_start      = $wazuh::params_agent::ossec_syscheck_scan_on_start,
  $ossec_syscheck_auto_ignore        = $wazuh::params_agent::ossec_syscheck_auto_ignore,
  $ossec_syscheck_directories_1      = $wazuh::params_agent::ossec_syscheck_directories_1,
  $ossec_syscheck_directories_2      = $wazuh::params_agent::ossec_syscheck_directories_2,

  $ossec_syscheck_report_changes_directories_1            = $wazuh::params_agent::ossec_syscheck_report_changes_directories_1,
  $ossec_syscheck_whodata_directories_1            = $wazuh::params_agent::ossec_syscheck_whodata_directories_1,
  $ossec_syscheck_realtime_directories_1           = $wazuh::params_agent::ossec_syscheck_realtime_directories_1,
  $ossec_syscheck_report_changes_directories_2         = $wazuh::params_agent::ossec_syscheck_report_changes_directories_2,
  $ossec_syscheck_whodata_directories_2            = $wazuh::params_agent::ossec_syscheck_whodata_directories_2,
  $ossec_syscheck_realtime_directories_2           = $wazuh::params_agent::ossec_syscheck_realtime_directories_2,
  $ossec_syscheck_ignore_list        = $wazuh::params_agent::ossec_syscheck_ignore_list,
  $ossec_syscheck_ignore_type_1      = $wazuh::params_agent::ossec_syscheck_ignore_type_1,
  $ossec_syscheck_ignore_type_2      = $wazuh::params_agent::ossec_syscheck_ignore_type_2,
  $ossec_syscheck_max_eps                      = $wazuh::params_agent::ossec_syscheck_max_eps,
  $ossec_syscheck_process_priority             = $wazuh::params_agent::ossec_syscheck_process_priority,
  $ossec_syscheck_synchronization_enabled      = $wazuh::params_agent::ossec_syscheck_synchronization_enabled,
  $ossec_syscheck_synchronization_interval     = $wazuh::params_agent::ossec_syscheck_synchronization_interval,
  $ossec_syscheck_synchronization_max_eps      = $wazuh::params_agent::ossec_syscheck_synchronization_max_eps,
  $ossec_syscheck_synchronization_max_interval = $wazuh::params_agent::ossec_syscheck_synchronization_max_interval,
  $ossec_syscheck_nodiff             = $wazuh::params_agent::ossec_syscheck_nodiff,
  $ossec_syscheck_skip_nfs           = $wazuh::params_agent::ossec_syscheck_skip_nfs,
  $ossec_syscheck_windows_audit_interval      = $wazuh::params_agent::windows_audit_interval,

  # Audit
  $audit_manage_rules                = $wazuh::params_agent::audit_manage_rules,
  $audit_buffer_bytes                = $wazuh::params_agent::audit_buffer_bytes,
  $audit_backlog_wait_time           = $wazuh::params_agent::audit_backlog_wait_time,
  $audit_rules                       = $wazuh::params_agent::audit_rules,

  # active-response
  $ossec_active_response_disabled             =  $wazuh::params_agent::active_response_disabled,
  $ossec_active_response_linux_ca_store       =  $wazuh::params_agent::active_response_linux_ca_store,
  $ossec_active_response_ca_verification      =  $wazuh::params_agent::active_response_ca_verification,
  $ossec_active_response_repeated_offenders   =  $wazuh::params_agent::active_response_repeated_offenders,

  # Agent Labels
  $ossec_labels                      = $wazuh::params_agent::ossec_labels,

  ## Selinux

  $selinux                           = $wazuh::params_agent::selinux,
  $manage_firewall                   = $wazuh::params_agent::manage_firewall,

  ## Windows

  $download_path                     = $wazuh::params_agent::download_path,

  # Logging
  $logging_log_format                = $wazuh::params_agent::logging_log_format,
) inherits wazuh::params_agent {
  # validate_bool(
  #   $ossec_active_response, $ossec_rootcheck,
  #   $selinux, $manage_repo,
  # )
  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  validate_legacy(String, 'validate_string', $agent_package_name)
  validate_legacy(String, 'validate_string', $agent_service_name)

  if (( $ossec_syscheck_whodata_directories_1 == 'yes' ) or ( $ossec_syscheck_whodata_directories_2 == 'yes' )) {
    class { 'wazuh::audit':
      audit_manage_rules      => $audit_manage_rules,
      audit_backlog_wait_time => $audit_backlog_wait_time,
      audit_buffer_bytes      => $audit_buffer_bytes,
      audit_rules             => $audit_rules,
    }
  }


  if $manage_client_keys == 'yes' {
    if $wazuh_register_endpoint == undef {
      fail('The $wazuh_register_endpoint parameter is needed in order to register the Agent.')
    }
  }

  # Package installation
  case $::kernel {
    'Linux': {
      if $manage_repo {
        class { 'wazuh::repo': }
        if $::osfamily == 'Debian' {
          Class['wazuh::repo'] -> Class['apt::update'] -> Package[$agent_package_name]
        } else {
          Class['wazuh::repo'] -> Package[$agent_package_name]
        }
      }
      package { $agent_package_name:
        ensure => "${agent_package_version}-${agent_package_revision}", # lint:ignore:security_package_pinned_version
      }
    }
    'windows': {
      file { $download_path:
        ensure => directory,
      }

      -> file { 'wazuh-agent':
        path               => "${download_path}\\wazuh-agent-${agent_package_version}-${agent_package_revision}.msi",
        group              => 'Administrators',
        mode               => '0774',
        source             => "${agent_msi_download_location}/wazuh-agent-${agent_package_version}-${agent_package_revision}.msi",
        source_permissions => ignore
      }

      # We dont need to pin the package version on Windows since we install if from the right MSI.
      -> package { $agent_package_name:
        ensure          => "${agent_package_version}",
        provider        => 'windows',
        source          => "${download_path}\\wazuh-agent-${agent_package_version}-${agent_package_revision}.msi",
        install_options => [
          '/q',
          "WAZUH_MANAGER=${wazuh_reporting_endpoint}",
          "WAZUH_PROTOCOL=${ossec_protocol}",
        ],
      }
    }
    default: { fail('OS not supported') }
  }

  case $::kernel {
  'Linux': {
    ## ossec.conf generation concats
    case $::operatingsystem {
      'RedHat', 'OracleLinux', 'Suse':{
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
      }'CentOS','Centos','centos','AlmaLinux','Rocky':{
        $apply_template_os = 'centos'
      }'SLES':{
        $apply_template_os = 'suse'
      }
      default: { fail('OS not supported') }
    }
  }'windows': {
      $apply_template_os = 'windows'
    }
    default: { fail('OS not supported') }
  }


  concat { 'agent_ossec.conf':
    path    => $wazuh::params_agent::config_file,
    owner   => $wazuh::params_agent::config_owner,
    group   => $wazuh::params_agent::config_group,
    mode    => $wazuh::params_agent::config_mode,
    before  => Service[$agent_service_name],
    require => Package[$agent_package_name],
    notify  => Service[$agent_service_name],
  }

  concat::fragment {
    'ossec.conf_header':
      target  => 'agent_ossec.conf',
      order   => 00,
      before  => Service[$agent_service_name],
      content => "<ossec_config>\n";
    'ossec.conf_agent':
      target  => 'agent_ossec.conf',
      order   => 10,
      before  => Service[$agent_service_name],
      content => template($ossec_conf_template);
  }

  if ($configure_rootcheck == true) {
    concat::fragment {
      'ossec.conf_rootcheck':
        target  => 'agent_ossec.conf',
        order   => 15,
        before  => Service[$agent_service_name],
        content => template($ossec_rootcheck_template);
    }
  }
  if ($configure_wodle_openscap == true) {
    concat::fragment {
      'ossec.conf_openscap':
        target  => 'agent_ossec.conf',
        order   => 16,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_openscap_template);
    }
  }
  if ($configure_wodle_cis_cat == true) {
    concat::fragment {
      'ossec.conf_cis_cat':
        target  => 'agent_ossec.conf',
        order   => 17,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_cis_cat_template);
    }
  }
  if ($configure_wodle_osquery == true) {
    concat::fragment {
      'ossec.conf_osquery':
        target  => 'agent_ossec.conf',
        order   => 18,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_osquery_template);
    }
  }
  if ($configure_wodle_syscollector == true) {
    concat::fragment {
      'ossec.conf_syscollector':
        target  => 'agent_ossec.conf',
        order   => 19,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_syscollector_template);
    }
  }
  if ($configure_wodle_docker_listener == true) {
    concat::fragment {
      'ossec.conf_docker_listener':
        target  => 'agent_ossec.conf',
        order   => 20,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_docker_listener_template);
    }
  }
  if ($configure_sca == true) {
    concat::fragment {
      'ossec.conf_sca':
        target  => 'agent_ossec.conf',
        order   => 25,
        before  => Service[$agent_service_name],
        content => template($ossec_sca_template);
    }
  }
  if ($configure_syscheck == true) {
    concat::fragment {
      'ossec.conf_syscheck':
        target  => 'agent_ossec.conf',
        order   => 30,
        before  => Service[$agent_service_name],
        content => template($ossec_syscheck_template);
    }
  }
  if ($configure_localfile == true) {
    concat::fragment {
      'ossec.conf_localfile':
        target  => 'agent_ossec.conf',
        order   => 35,
        before  => Service[$agent_service_name],
        content => template($ossec_localfile_template);
    }
  }
  if ($configure_active_response == true) {
    wazuh::activeresponse { 'active-response configuration':
      active_response_disabled           =>  $ossec_active_response_disabled,
      active_response_linux_ca_store     =>  $ossec_active_response_linux_ca_store,
      active_response_ca_verification    =>  $ossec_active_response_ca_verification,
      active_response_repeated_offenders =>  $ossec_active_response_repeated_offenders,
      order_arg                          => 40,
      before_arg                         => Service[$agent_service_name],
      target_arg                         => 'agent_ossec.conf'
    }
  }

  if ($configure_labels == true){
    concat::fragment {
        'ossec.conf_labels':
        target  => 'agent_ossec.conf',
        order   => 45,
        before  => Service[$agent_service_name],
        content => template($ossec_labels_template);
    }
  }

  concat::fragment {
    'ossec.conf_footer':
      target  => 'agent_ossec.conf',
      order   => 99,
      before  => Service[$agent_service_name],
      content => '</ossec_config>';
  }

  # Agent registration and service setup
  if ($manage_client_keys == 'yes') {
    if $agent_name {
      validate_legacy(String, 'validate_string', $agent_name)
      $agent_auth_option_name = "-A \"${agent_name}\""
    } else {
      $agent_auth_option_name = ''
    }

    if $agent_group {
      validate_legacy(String, 'validate_string', $agent_group)
      $agent_auth_option_group = "-G \"${agent_group}\""
    } else {
      $agent_auth_option_group = ''
    }

    if $agent_auth_password {
      $agent_auth_option_password = "-P \"${agent_auth_password}\""
    } else {
      $agent_auth_option_password = ''
    }

    if $agent_address {
      $agent_auth_option_address = "-I \"${agent_address}\""
    } else {
      $agent_auth_option_address = ''
    }

    case $::kernel {
      'Linux': {
        file { $::wazuh::params_agent::keys_file:
          owner => $wazuh::params_agent::keys_owner,
          group => $wazuh::params_agent::keys_group,
          mode  => $wazuh::params_agent::keys_mode,
        }

        $agent_auth_executable = '/var/ossec/bin/agent-auth'
        $agent_auth_base_command = "${agent_auth_executable} -m ${wazuh_register_endpoint}"

        # https://documentation.wazuh.com/4.0/user-manual/registering/manager-verification/manager-verification-registration.html
        if $wazuh_manager_root_ca_pem != undef {
          validate_legacy(String, 'validate_string', $wazuh_manager_root_ca_pem)
          file { '/var/ossec/etc/rootCA.pem':
            owner   => $wazuh::params_agent::keys_owner,
            group   => $wazuh::params_agent::keys_group,
            mode    => $wazuh::params_agent::keys_mode,
            content => $wazuh_manager_root_ca_pem,
            require => Package[$agent_package_name],
          }
          $agent_auth_option_manager = '-v /var/ossec/etc/rootCA.pem'
        } elsif $wazuh_manager_root_ca_pem_path != undef {
          validate_legacy(String, 'validate_string', $wazuh_manager_root_ca_pem)
          $agent_auth_option_manager = "-v ${wazuh_manager_root_ca_pem_path}"
        } else {
          $agent_auth_option_manager = ''  # Avoid errors when compounding final command
        }

        # https://documentation.wazuh.com/4.0/user-manual/registering/manager-verification/agent-verification-registration.html
        if ($wazuh_agent_cert != undef) and ($wazuh_agent_key != undef) {
          validate_legacy(String, 'validate_string', $wazuh_agent_cert)
          validate_legacy(String, 'validate_string', $wazuh_agent_key)
          file { '/var/ossec/etc/sslagent.cert':
            owner   => $wazuh::params_agent::keys_owner,
            group   => $wazuh::params_agent::keys_group,
            mode    => $wazuh::params_agent::keys_mode,
            content => $wazuh_agent_cert,
            require => Package[$agent_package_name],
          }
          file { '/var/ossec/etc/sslagent.key':
            owner   => $wazuh::params_agent::keys_owner,
            group   => $wazuh::params_agent::keys_group,
            mode    => $wazuh::params_agent::keys_mode,
            content => $wazuh_agent_key,
            require => Package[$agent_package_name],
          }

          $agent_auth_option_agent = '-x /var/ossec/etc/sslagent.cert -k /var/ossec/etc/sslagent.key'
        } elsif ($wazuh_agent_cert_path != undef) and ($wazuh_agent_key_path != undef) {
          validate_legacy(String, 'validate_string', $wazuh_agent_cert_path)
          validate_legacy(String, 'validate_string', $wazuh_agent_key_path)
          $agent_auth_option_agent = "-x ${wazuh_agent_cert_path} -k ${wazuh_agent_key_path}"
        } else {
          $agent_auth_option_agent = ''
        }

        $agent_auth_command = "${agent_auth_base_command} ${agent_auth_option_name} ${agent_auth_option_group} \
          ${agent_auth_option_manager}  ${agent_auth_option_agent} ${agent_auth_option_password} ${agent_auth_option_address}"

        exec { 'agent-auth-linux':
          command => $agent_auth_command,
          unless  => "/bin/egrep -q '.' ${::wazuh::params_agent::keys_file}",
          require => Concat['agent_ossec.conf'],
          before  => Service[$agent_service_name],
          notify  => Service[$agent_service_name],
        }

        service { $agent_service_name:
          ensure    => $agent_service_ensure,
          enable    => true,
          hasstatus => $wazuh::params_agent::service_has_status,
          pattern   => $wazuh::params_agent::agent_service_name,
          provider  => $wazuh::params_agent::ossec_service_provider,
          require   => Package[$agent_package_name],
        }
      }
      'windows': {
        $agent_auth_executable = "'C:\\Program Files (x86)\\ossec-agent\\agent-auth.exe'"
        $agent_auth_base_command = "& ${agent_auth_executable} -m \"${wazuh_register_endpoint}\""

        # TODO: Implement the support for Manager verification using SSL
        # TODO: Implement the support for Agent verification using SSL

        $agent_auth_command = "${agent_auth_base_command} ${agent_auth_option_name} ${agent_auth_option_group} \
          ${agent_auth_option_password}"

        exec { 'agent-auth-windows':
          command  => $agent_auth_command,
          provider => 'powershell',
          onlyif   => "if ((Get-Item '${$::wazuh::params_agent::keys_file}').length -gt 0kb) {exit 1}",
          require  => Concat['agent_ossec.conf'],
          before   => Service[$agent_service_name],
          notify   => Service[$agent_service_name],
        }

        service { $agent_service_name:
          ensure    => $agent_service_ensure,
          enable    => true,
          hasstatus => $wazuh::params_agent::service_has_status,
          pattern   => $wazuh::params_agent::agent_service_name,
          provider  => $wazuh::params_agent::ossec_service_provider,
          require   => Package[$agent_package_name],
        }
      }
      default: { fail('OS not supported') }
    }
  } else {
    service { $agent_service_name:
      ensure    => stopped,
      enable    => false,
      hasstatus => $wazuh::params_agent::service_has_status,
      pattern   => $agent_service_name,
      provider  => $wazuh::params_agent::ossec_service_provider,
      require   => Package[$agent_package_name],
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
      dport  => $ossec_port,
      proto  => $ossec_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED',
      ],
    }
  }

  if ( $wazuh_enrollment_auth_pass ) {
    file { $wazuh::params_agent::authd_pass_file:
      owner   => 'root',
      group   => 'wazuh',
      mode    => '0640',
      content => $wazuh_enrollment_auth_pass,
      require => Package[$wazuh::params_agent::agent_package_name],
    }
  }

}
