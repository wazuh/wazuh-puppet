# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Setup for ossec client
class wazuh::agent(

  # Versioning and package names

  $agent_package_version             = $wazuh::params_agent::agent_package_version,
  $agent_package_name                = $wazuh::params_agent::agent_package_name,
  $agent_service_name                = $wazuh::params_agent::agent_service_name,

  # Manage repository

  $manage_repo                       = $wazuh::params_agent::manage_repo,

  # Authd registration options
  $manage_client_keys                = $wazuh::params_agent::manage_client_keys,
  $agent_name                        = $wazuh::params_agent::agent_name,
  $agent_group                       = $wazuh::params_agent::agent_group,
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
  $configure_sca                     = $wazuh::params_agent::configure_sca,
  $configure_syscheck                = $wazuh::params_agent::configure_syscheck,
  $configure_localfile               = $wazuh::params_agent::configure_localfile,
  $configure_active_response         = $wazuh::params_agent::configure_active_response,

  # Templates paths
  $ossec_conf_template               = $wazuh::params_agent::ossec_conf_template,
  $ossec_rootcheck_template          = $wazuh::params_agent::ossec_rootcheck_template,
  $ossec_wodle_openscap_template     = $wazuh::params_agent::ossec_wodle_openscap_template,
  $ossec_wodle_cis_cat_template      = $wazuh::params_agent::ossec_wodle_cis_cat_template,
  $ossec_wodle_osquery_template      = $wazuh::params_agent::ossec_wodle_osquery_template,
  $ossec_wodle_syscollector_template = $wazuh::params_agent::ossec_wodle_syscollector_template,
  $ossec_sca_template                = $wazuh::params_agent::ossec_sca_template,
  $ossec_syscheck_template           = $wazuh::params_agent::ossec_syscheck_template,
  $ossec_localfile_template          = $wazuh::params_agent::ossec_localfile_template,
  $ossec_ruleset                     = $wazuh::params_agent::ossec_ruleset,
  $ossec_auth                        = $wazuh::params_agent::ossec_auth,
  $ossec_cluster                     = $wazuh::params_agent::ossec_cluster,
  $ossec_active_response_template    = $wazuh::params_agent::ossec_active_response_template,

  # Server configuration

  $wazuh_register_endpoint           = $wazuh::params_agent::wazuh_register_endpoint,
  $wazuh_reporting_endpoint          = $wazuh::params_agent::wazuh_reporting_endpoint,
  $ossec_port                        = $wazuh::params_agent::ossec_port,
  $ossec_protocol                    = $wazuh::params_agent::ossec_protocol,
  $ossec_notify_time                 = $wazuh::params_agent::ossec_notify_time,
  $ossec_time_reconnect              = $wazuh::params_agent::ossec_time_reconnect,
  $ossec_auto_restart                = $wazuh::params_agent::ossec_auto_restart,
  $ossec_crypto_method               = $wazuh::params_agent::ossec_crypto_method,
  $client_buffer_queue_size          = $wazuh::params_agent::client_buffer_queue_size,
  $client_buffer_events_per_second   = $wazuh::params_agent::client_buffer_events_per_second,

  # Rootcheck
  $ossec_rootcheck_disabled          = $wazuh::params_agent::ossec_rootcheck_disabled,
  $ossec_rootcheck_check_files       = $wazuh::params_agent::ossec_rootcheck_check_files,
  $ossec_rootcheck_check_trojans     = $wazuh::params_agent::ossec_rootcheck_check_trojans,
  $ossec_rootcheck_check_dev         = $wazuh::params_agent::ossec_rootcheck_check_dev,
  $ossec_rootcheck_check_sys         = $wazuh::params_agent::ossec_rootcheck_check_sys,
  $ossec_rootcheck_check_pids        = $wazuh::params_agent::ossec_rootcheck_check_pids,
  $ossec_rootcheck_check_ports       = $wazuh::params_agent::ossec_rootcheck_check_ports,
  $ossec_rootcheck_check_if          = $wazuh::params_agent::ossec_rootcheck_check_if,
  $ossec_rootcheck_frequency         = $wazuh::params_agent::ossec_rootcheck_frequency,
  $ossec_rootcheck_rootkit_files     = $wazuh::params_agent::ossec_rootcheck_rootkit_files,
  $ossec_rootcheck_rootkit_trojans   = $wazuh::params_agent::ossec_rootcheck_rootkit_trojans,
  $ossec_rootcheck_skip_nfs          = $wazuh::params_agent::ossec_rootcheck_skip_nfs,

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

  # Localfile
  $ossec_local_files                 = $wazuh::params_agent::default_local_files,

  # Syscheck
  $ossec_syscheck_disabled           = $wazuh::params_agent::ossec_syscheck_disabled,
  $ossec_syscheck_frequency          = $wazuh::params_agent::ossec_syscheck_frequency,
  $ossec_syscheck_scan_on_start      = $wazuh::params_agent::ossec_syscheck_scan_on_start,
  $ossec_syscheck_alert_new_files    = $wazuh::params_agent::ossec_syscheck_alert_new_files,
  $ossec_syscheck_auto_ignore        = $wazuh::params_agent::ossec_syscheck_auto_ignore,
  $ossec_syscheck_directories_1      = $wazuh::params_agent::ossec_syscheck_directories_1,
  $ossec_syscheck_directories_2      = $wazuh::params_agent::ossec_syscheck_directories_2,
  $ossec_syscheck_ignore_list        = $wazuh::params_agent::ossec_syscheck_ignore_list,
  $ossec_syscheck_ignore_type_1      = $wazuh::params_agent::ossec_syscheck_ignore_type_1,
  $ossec_syscheck_ignore_type_2      = $wazuh::params_agent::ossec_syscheck_ignore_type_2,
  $ossec_syscheck_nodiff             = $wazuh::params_agent::ossec_syscheck_nodiff,
  $ossec_syscheck_skip_nfs           = $wazuh::params_agent::ossec_syscheck_skip_nfs,

  ## Selinux

  $selinux                           = $wazuh::params_agent::selinux,
  $manage_firewall                   = $wazuh::params_agent::manage_firewall,

  ## Windows

  $download_path                     = $wazuh::params_agent::download_path,


) inherits wazuh::params_agent {
  # validate_bool(
  #   $ossec_active_response, $ossec_rootcheck,
  #   $selinux, $manage_repo, 
  # )
  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  validate_string($agent_package_name)
  validate_string($agent_service_name)

  if (($manage_client_keys == 'yes')){
      if ( ( $wazuh_register_endpoint == undef ) ) {
        fail('The $wazuh_register_endpoint parameter is needed in order to register the Agent.')
      }
  }

  case $::kernel {
    'Linux' : {
      if $manage_repo {
        class { 'wazuh::repo':}
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

      file { 'wazuh-agent':
          path               => "${download_path}wazuh-agent-${agent_package_version}.msi",
          owner              => 'Administrator',
          group              => 'Administrators',
          mode               => '0774',
          source             => "http://packages.wazuh.com/3.x/windows/wazuh-agent-${agent_package_version}.msi",
          source_permissions => ignore
      }

      if ( $manage_client_keys == 'yes' ) {
        package { $agent_package_name:
          ensure          => $agent_package_version, # lint:ignore:security_package_pinned_version
          provider        => 'windows',
          source          => "${download_path}/wazuh-agent-${agent_package_version}.msi",
          install_options => [ '/q', "ADDRESS=${wazuh_register_endpoint}", "AUTHD_SERVER=${wazuh_register_endpoint}" ],
          require         => File["${download_path}wazuh-agent-${agent_package_version}.msi"],
        }
      }
      else {
        package { $agent_package_name:
          ensure          => $agent_package_version, # lint:ignore:security_package_pinned_version
          provider        => 'windows',
          source          => "${download_path}wazuh-agent-${agent_package_version}.msi",
          install_options => [ '/q' ],  # silent installation
          require         => File["${download_path}wazuh-agent-${agent_package_version}.msi"],
        }
      }
    }
    default: { fail('OS not supported') }
  }

  ## ossec.conf generation concats

  case $::operatingsystem{
    'Redhat', 'redhat':{
      $apply_template_os = 'rhel'
      if ( $::operatingsystemrelease     =~ /^7.*/ ){
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

  concat { 'ossec.conf':
    path    => $wazuh::params_agent::config_file,
    owner   => $wazuh::params_agent::config_owner,
    group   => $wazuh::params_agent::config_group,
    mode    => $wazuh::params_agent::config_mode,
    require => Package[$agent_package_name],
  }

  concat::fragment {
    default:
      target => 'ossec.conf';
    'ossec.conf_header':
      order   => 00,
      before  => Service[$agent_service_name],
      content => "<ossec_config>\n";
    'ossec.conf_agent':
      order   => 10,
      before  => Service[$agent_service_name],
      content => template($ossec_conf_template);
  }
  if ($configure_rootcheck == true){
    concat::fragment {
        'ossec.conf_rootcheck':
        target  => 'ossec.conf',
        order   => 15,
        before  => Service[$agent_service_name],
        content => template($ossec_rootcheck_template);
    }
  }
  if ($configure_wodle_openscap == true){
    concat::fragment {
        'ossec.conf_openscap':
        target  => 'ossec.conf',
        order   => 16,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_openscap_template);
    }
  }
  if ($configure_wodle_cis_cat == true){
    concat::fragment {
        'ossec.conf_cis_cat':
        target  => 'ossec.conf',
        order   => 17,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_cis_cat_template);
    }
  }
  if ($configure_wodle_osquery == true){
    concat::fragment {
        'ossec.conf_osquery':
        target  => 'ossec.conf',
        order   => 18,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_osquery_template);
    }
  }
  if ($configure_wodle_syscollector == true){
    concat::fragment {
        'ossec.conf_syscollector':
        target  => 'ossec.conf',
        order   => 19,
        before  => Service[$agent_service_name],
        content => template($ossec_wodle_syscollector_template);
    }
  }
  if ($configure_sca == true){
    concat::fragment {
        'ossec.conf_sca':
        target  => 'ossec.conf',
        order   => 25,
        before  => Service[$agent_service_name],
        content => template($ossec_sca_template);
    }
  }
  if ($configure_syscheck == true){
    concat::fragment {
        'ossec.conf_syscheck':
        target  => 'ossec.conf',
        order   => 30,
        before  => Service[$agent_service_name],
        content => template($ossec_syscheck_template);
    }
  }
  if ($configure_localfile == true){
    concat::fragment {
        'ossec.conf_localfile':
        target  => 'ossec.conf',
        order   => 35,
        before  => Service[$agent_service_name],
        content => template($ossec_localfile_template);
    }
  }
  if ($configure_active_response == true){
    concat::fragment {
        'ossec.conf_active_response':
        target  => 'ossec.conf',
        order   => 40,
        before  => Service[$agent_service_name],
        content => template($ossec_active_response_template);
    }
  }
  concat::fragment {
      'ossec.conf_footer':
      target  => 'ossec.conf',
      order   => 99,
      before  => Service[$agent_service_name],
      content => '</ossec_config>';
  }

  if ($manage_client_keys == 'yes'){

    if ($::kernel == 'Linux') {
      # Is this really Linux only?

      file { $::wazuh::params_agent::keys_file:
        owner => $wazuh::params_agent::keys_owner,
        group => $wazuh::params_agent::keys_group,
        mode  => $wazuh::params_agent::keys_mode,
      }

      # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl

      $agent_auth_base_command = "/var/ossec/bin/agent-auth -m ${wazuh_register_endpoint}"

      if $wazuh_manager_root_ca_pem != undef {
        validate_string($wazuh_manager_root_ca_pem)
        file { '/var/ossec/etc/rootCA.pem':
          owner   => $wazuh::params::keys_owner,
          group   => $wazuh::params::keys_group,
          mode    => $wazuh::params::keys_mode,
          content => $wazuh_manager_root_ca_pem,
          require => Package[$agent_package_name],
        }
        $agent_auth_option_manager = '-v /var/ossec/etc/rootCA.pem'
      }elsif $wazuh_manager_root_ca_pem_path != undef {
        validate_string($wazuh_manager_root_ca_pem)
        $agent_auth_option_manager = "-v ${wazuh_manager_root_ca_pem_path}"
      } else {
        $agent_auth_option_manager = ''  # Avoid errors when compounding final command
      }

      if $agent_name != undef {
        validate_string($agent_name)
        $agent_auth_option_name = "-A \"${agent_name}\""
      }else{
        $agent_auth_option_name = ''
      }

      if $agent_group != undef {
        validate_string($agent_group)
        $agent_auth_option_group = "-G \"${agent_group}\""
      }else{
        $agent_auth_option_group = ''
      }

    # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-agents-via-ssl
    if ($wazuh_agent_cert != undef) and ($wazuh_agent_key != undef) {
      validate_string($wazuh_agent_cert)
      validate_string($wazuh_agent_key)
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
    }

    if ($wazuh_agent_cert_path != undef) and ($wazuh_agent_key_path != undef) {
      validate_string($wazuh_agent_cert_path)
      validate_string($wazuh_agent_key_path)
      $agent_auth_option_agent = "-x ${wazuh_agent_cert_path} -k ${wazuh_agent_key_path}"
    }

    $agent_auth_command = "${agent_auth_base_command} ${agent_auth_option_manager} ${agent_auth_option_name}\
     ${agent_auth_option_group} ${agent_auth_option_agent}"

      if $agent_auth_password {
        exec { 'agent-auth-with-pwd':
          command => "${agent_auth_command} -P '${agent_auth_password}'",
          unless  => "/bin/egrep -q '.' ${::wazuh::params_agent::keys_file}",
          require => Concat['ossec.conf'],
          before  => Service[$agent_service_name],
          }
      } else {
        exec { 'agent-auth-without-pwd':
          command => $agent_auth_command,
          unless  => "/bin/egrep -q '.' ${::wazuh::params_agent::keys_file}",
          require => Concat['ossec.conf'],
          before  => Service[$agent_service_name],
        }
      }
      if $wazuh_reporting_endpoint != undef {
        service { $agent_service_name:
          ensure    => running,
          enable    => true,
          hasstatus => $wazuh::params_agent::service_has_status,
          pattern   => $wazuh::params_agent::agent_service_name,
          provider  => $wazuh::params_agent::ossec_service_provider,
          require   => Package[$agent_package_name],
        }
      }
    }
  }

  if ( ( $manage_client_keys != 'yes') or ( $wazuh_reporting_endpoint == undef ) ){
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
        'ESTABLISHED'],
    }
  }
}

