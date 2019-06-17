# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Main ossec server config
class wazuh::manager (
    $ossec_local_files = $::wazuh::params_manager::default_local_files
) inherits wazuh::params_manager {
  validate_bool(
    $manage_repos, $manage_epel_repo, $syslog_output,$wazuh_manager_verify_manager_ssl
  )
  validate_array(
    $decoder_exclude, $rule_exclude
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

  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  if ($ossec_emailnotification == true) {
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
    provider  => $ossec_service_provider,
    require   => Package[$wazuh::params_manager::server_package],
  }

  ## Declaring variables for localfile and wodles generation
  
  if $::osfamily == 'Debian' {
    $apply_template_os = "debian"
  }else{
    $apply_template_os = "centos"
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
      target => 'ossec.conf',
      order   => 00,
      content => "<ossec_config>\n";
    'ossec.conf_main':
      target => 'ossec.conf',
      order => 01,
      content => template('wazuh/wazuh_manager.conf.erb');
  }
  if($configure_rootcheck == true){
    concat::fragment {
        'ossec.conf_rootcheck':
          order => 10,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_rootcheck_linux.erb');
      }6
  }

  if ($configure_wodle_openscap == true){
    concat::fragment {
      'ossec.conf_wodle_openscap':
        order => 15,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_openscap.erb');
    }
  }
  if ($configure_wodle_cis_cat == true){
    concat::fragment {
      'ossec.conf_wodle_ciscat':
        order => 20,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_cis_cat.erb');
    }
  }
  if ($configure_wodle_osquery== true){
    concat::fragment {
      'ossec.conf_wodle_osquery':
        order => 25,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_osquery.erb');
    }
  }
  if ($configure_wodle_syscollector == true){
    concat::fragment {
      'ossec.conf_wodle_syscollector':
        order => 30,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_syscollector.erb');
    }
  }
  if ($configure_sca == true){
    concat::fragment {
      'ossec.conf_sca':
        order => 40,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_sca.erb');
      }
  }
  if($configure_vulnerability_detector == true){
    concat::fragment {
      'ossec.conf_wodle_vulnerability_detector':
        order => 45,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_wodle_vulnerability_detector.erb');
    }
  }
  if($configure_syscheck == true){
    concat::fragment {
      'ossec.conf_syscheck':
        order => 55,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_syscheck.erb');
    }
  }
  if ($configure_command == true){
    concat::fragment {
          'ossec.conf_command':
            order => 60,
            target => 'ossec.conf',
            content => template('wazuh/command.erb');
      }
  }
  if ($configure_localfile == true){
    concat::fragment {
      'ossec.conf_localfile':
        order => 65,
        target => 'ossec.conf',
        content => template('wazuh/fragments/_localfile.erb');
    }
  }
  if($configure_ruleset == true){
    concat::fragment {
        'ossec.conf_ruleset':
          order => 75,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_ruleset.erb');
      }
  }
  if ($configure_auth == true){
    concat::fragment {
        'ossec.conf_auth':
          order => 80,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_auth.erb');
      }
  }
  if ($configure_cluster == true){
    concat::fragment {
        'ossec.conf_cluster':
          order => 85,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_cluster.erb');
      }
  }
  if ($configure_active_response == true){
    concat::fragment {
        'ossec.conf_active_response':
          order => 90,
          target => 'ossec.conf',
          content => template('wazuh/fragments/_activeresponse.erb');
      }
  }
  concat::fragment {
    'ossec.conf_footer':
      target => 'ossec.conf',
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
  if $manage_firewall {
    include firewall
    firewall { '1514 wazuh-manager':
      dport  => $manager_port,
      proto  => $manager_protocol,
      action => 'accept',
      state  => [
        'NEW',
        'RELATED',
        'ESTABLISHED'],
    }
  }
}
