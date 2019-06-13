# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Main ossec server config
class wazuh::manager (
    $ossec_local_files = $::wazuh::params::default_local_files
) inherits wazuh::params {
  validate_bool(
    $manage_repos, $manage_epel_repo, $syslog_output,$wazuh_manager_verify_manager_ssl
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
  }
  concat::fragment {
    'ossec.conf_header':
      target => 'ossec.conf',
      order   => 00,
      content => "<ossec_config>\n";
    'ossec.conf_main':
      target => 'ossec.conf',
      order => 01,
      content => template('wazuh/wazuh_manager.conf.erb');
  }
  if($rootcheck_configure == true){
    concat::fragment {
        'ossec.conf_rootcheck':
          order => 10,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_rootcheck_linux.erb');
      }6
  }

  if ($wodle_openscap_configure == true){
    concat::fragment {
      'ossec.conf_wodle_openscap':
        order => 15,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_openscap.erb');
    }
  }
  if ($wodle_ciscat_configure == true){
    concat::fragment {
      'ossec.conf_wodle_ciscat':
        order => 20,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_cis_cat.erb');
    }
  }
  if ($wodle_osquery_configure == true){
    concat::fragment {
      'ossec.conf_wodle_osquery':
        order => 25,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_osquery.erb');
    }
  }
  if ($wodle_syscollector_configure == true){
    concat::fragment {
      'ossec.conf_wodle_syscollector':
        order => 30,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_syscollector.erb');
    }
  }
  if ($sca_configure == true){
    if ($::osfamily == 'RedHat'){
      concat::fragment {
        'ossec.conf_sca':
          order => 35,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_sca_centos.erb');
      }
    }else{
      concat::fragment {
        'ossec.conf_sca':
          order => 40,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_sca_debian.erb');
      }
    }
  }
  if($wodle_vulnerability_detector_configure == true){
    concat::fragment {
        'ossec.conf_wodle_vulnerability_detector':
          order => 45,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_wodle_vulnerability_detector.erb');
      }
  }
  if($syscheck_configure == true){
    if ($::kernel == 'Linux') {
      concat::fragment {
          'ossec.conf_syscheck':
            order => 50,
            target => 'ossec.conf',
            content => template('wazuh/fragments/_syscheck_linux.erb');
      }
    }else{
      concat::fragment {
          'ossec.conf_syscheck':
            order => 55,
            target => 'ossec.conf',
            content => template('wazuh/fragments/_syscheck_windows.erb');
      }
    }
  }
  if ($command_configure == true){
    concat::fragment {
          'ossec.conf_command':
            order => 60,
            target => 'ossec.conf',
            content => template('wazuh/command.erb');
      }
  }
  if ($localfile_configure == true){
    concat::fragment {
      'ossec.conf_localfile':
        order => 65,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_localfile.erb');
    }
  }
  if($ruleset_configure == true){
    concat::fragment {
        'ossec.conf_ruleset':
          order => 75,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_ruleset.erb');
      }
  }
  if ($auth_configure == true){
    concat::fragment {
        'ossec.conf_auth':
          order => 80,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_auth.erb');
      }
  }
  if ($cluster_configure == true){
    concat::fragment {
        'ossec.conf_cluster':
          order => 85,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_cluster.erb');
      }
  }
  concat::fragment {
    'ossec.conf_footer':
      target => 'ossec.conf',
      order   => 99,
      content => "</ossec_config>\n";
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
