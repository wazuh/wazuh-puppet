# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Setup for ossec client
class wazuh::agent(
  

) inherits wazuh::params_agent {
  validate_bool(
    $ossec_active_response, $ossec_rootcheck,
    $selinux, $manage_repo, $manage_epel_repo
  )
  # This allows arrays of integers, sadly
  # (commented due to stdlib version requirement)
  validate_string($agent_package_name)
  validate_string($agent_service_name)

  if ( ( $ossec_server_ip == undef ) and ( $ossec_server_hostname == undef ) and ( $wazuh_manager_address == undef ) ) {
    fail('must pass either $ossec_server_ip or $ossec_server_hostname or $wazuh_manager_address to Class[\'wazuh::agent\'].')
  }

  case $::kernel {
    'Linux' : {
      if $manage_repo {
        class { 'wazuh::repo': redhat_manage_epel => $manage_epel_repo }
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

      file {

        'C:/wazuh-agent-3.9.1-1.msi':
          owner              => 'Administrators',
          group              => 'Administrators',
          mode               => '0774',
          source             => 'puppet:///modules/wazuh/wazuh-agent-3.9.1-1.msi',
          source_permissions => ignore
      }
      if ( $manage_client_keys == 'authd' ) {
        package { $agent_package_name:
          ensure          => $agent_package_version, # lint:ignore:security_package_pinned_version
          provider        => 'windows',
          source          => 'C:/wazuh-agent-3.9.1-1.msi',
          install_options => [ '/q', "ADDRESS=${ossec_server_ip}", "AUTHD_SERVER=${ossec_server_ip}" ],  # silent installation
          require         => File['C:/wazuh-agent-3.9.1-1.msi'],
        }
      }
      else {
        package { $agent_package_name:
          ensure          => $agent_package_version, # lint:ignore:security_package_pinned_version
          provider        => 'windows',
          source          => 'C:/wazuh-agent-3.9.1-1.msi',
          install_options => [ '/q' ],  # silent installation
          require         => File['C:/wazuh-agent-3.9.1-1.msi'],
        }
      }
    }
    default: { fail('OS not supported') }
  }

  service { $agent_service_name:
    ensure    => running,
    enable    => true,
    hasstatus => $service_has_status,
    pattern   => $agent_service_name,
    provider  => $ossec_service_provider,
    require   => Package[$agent_package_name],
  }

  ## ossec.conf generation concats

  concat { 'ossec.conf':
    path    => $wazuh::params::config_file,
    owner   => $wazuh::params::config_owner,
    group   => $wazuh::params::config_group,
    mode    => $wazuh::params::config_mode,
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
  }
  if ($configure_rootcheck == true){
    concat::fragment {
        'ossec.conf_rootcheck':
        target  => 'ossec.conf',
        order   => 15,
        content => template($ossec_rootcheck_template);
    }
  }
  if ($configure_wodle_openscap == true){
    concat::fragment {
        'ossec.conf_openscap':
        target  => 'ossec.conf',
        order   => 16,
        content => template($ossec_wodle_openscap_template);
    }
  }
  if ($configure_wodle_cis_cat == true){
    concat::fragment {
        'ossec.conf_cis_cat':
        target  => 'ossec.conf',
        order   => 17,
        content => template($ossec_wodle_cis_cat_template);
    }
  }
  if ($configure_wodle_osquery == true){
    concat::fragment {
        'ossec.conf_osquery':
        target  => 'ossec.conf',
        order   => 18,
        content => template($ossec_wodle_osquery_template);
    }
  }
  if ($configure_wodle_syscollector == true){
    concat::fragment {
        'ossec.conf_syscollector':
        target  => 'ossec.conf',
        order   => 19,
        content => template($ossec_wodle_syscollector_template);
    }
  }
  if ($configure_sca == true){
    concat::fragment {
        'ossec.conf_sca':
        target  => 'ossec.conf',
        order   => 25,
        content => template($ossec_sca_template);
    }
  }
  if ($configure_syscheck == true){
    concat::fragment {
        'ossec.conf_syscheck':
        target  => 'ossec.conf',
        order   => 30,
        content => template($ossec_syscheck_template);
    }
  }
  if ($configure_localfile == true){
    concat::fragment {
        'ossec.conf_localfile':
        target  => 'ossec.conf',
        order   => 35,
        content => template($ossec_localfile_template);
    }
  }
  if ($configure_active_response == true){
    concat::fragment {
        'ossec.conf_active_response':
        target  => 'ossec.conf',
        order   => 40,
        content => template($ossec_active_response_template);
    }
  }
  
  concat::fragment {
      'ossec.conf_footer':
      target  => 'ossec.conf',
      order   => 99,
      content => '</ossec_config>';
  }

  if ($manage_client_keys == 'authd') {
    if ($::kernel == 'Linux') {
      # Is this really Linux only?
      $ossec_server_address = pick($ossec_server_ip, $ossec_server_hostname)

      file { $::wazuh::params::keys_file:
        owner => $wazuh::params::keys_owner,
        group => $wazuh::params::keys_group,
        mode  => $wazuh::params::keys_mode,
      }

      # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-manager-via-ssl

      $agent_auth_base_command = "/var/ossec/bin/agent-auth -m ${ossec_server_address} -A ${agent_name} -G ${agent_group} -D /var/ossec/"
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
      }
      if $wazuh_manager_root_ca_pem_path != undef {
        validate_string($wazuh_manager_root_ca_pem)
        $agent_auth_option_manager = "-v ${wazuh_manager_root_ca_pem_path}"
      }

    # https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#verify-agents-via-ssl
    if ($wazuh_agent_cert != undef) and ($wazuh_agent_key != undef) {
      validate_string($wazuh_agent_cert)
      validate_string($wazuh_agent_key)
      file { '/var/ossec/etc/sslagent.cert':
        owner   => $wazuh::params::keys_owner,
        group   => $wazuh::params::keys_group,
        mode    => $wazuh::params::keys_mode,
        content => $wazuh_agent_cert,
        require => Package[$agent_package_name],
      }
      file { '/var/ossec/etc/sslagent.key':
        owner   => $wazuh::params::keys_owner,
        group   => $wazuh::params::keys_group,
        mode    => $wazuh::params::keys_mode,
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

    $agent_auth_command = "${agent_auth_base_command} ${agent_auth_option_manager} ${agent_auth_option_agent}"

      if $agent_auth_password {
        exec { 'agent-auth-with-pwd':
          command => "${agent_auth_command} -P '${agent_auth_password}'",
          unless  => "/bin/egrep -q '.' ${::wazuh::params::keys_file}",
          require => Package[$agent_package_name],
          notify  => Service[$agent_service_name],
          before  => File[$wazuh::params::keys_file]
          }
      } else {
        exec { 'agent-auth-without-pwd':
          command => $agent_auth_command,
          unless  => "/bin/egrep -q '.' ${::wazuh::params::keys_file}",
          require => Package[$agent_package_name],
          notify  => Service[$agent_service_name],
          before  => File[$wazuh::params::keys_file],
        }
      }
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
