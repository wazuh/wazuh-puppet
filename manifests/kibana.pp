# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Setup for Kibana
class wazuh::kibana (
  $kibana_package = 'kibana',
  $kibana_service = 'kibana',
  $kibana_version = '7.10.2',

  $kibana_elasticsearch_hosts = [
    {
      host  => 'localhost',
      port  => 9200,
      proto => 'http',
    },
  ],

  # Node used for API queries
  $kibana_elasticsearch_ip = $kibana_elasticsearch_hosts[0]['host'],
  $kibana_elasticsearch_port = $kibana_elasticsearch_hosts[0]['port'],
  $kibana_elasticsearch_proto = $kibana_elasticsearch_hosts[0]['proto'],
  
  $elasticsearch_username = undef,
  $elasticsearch_password = undef,
  $elasticsearch_ssl_verificationmode = undef,

  $kibana_server_port = '5601',
  $kibana_server_host = '0.0.0.0',
  $kibana_wazuh_version = '4.3.0',

  $server_ssl = false,
  $server_ssl_certificate = undef,
  $server_ssl_key = undef,

  # app variables
  $kibana_app_version = "${kibana_wazuh_version}_${$kibana_version}",
  $kibana_app_url = "https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-${kibana_app_version}-1.zip",
  $kibana_app_reinstall = false,
  $kibana_app_node_options = '--no-warnings --max-old-space-size=2048 --max-http-header-size=65536',

  # user/group kibana processes run as
  $kibana_user = 'kibana',
  $kibana_group = 'kibana',

  $kibana_wazuh_api_credentials = [ {
                                      'id'       => 'default',
                                      'url'      => 'http://localhost',
                                      'port'     => '55000',
                                      'user'     => 'wazuh',
                                      'password' => 'wazuh',
                                    },
                                  ],

  # kibana paths
  $kibana_path_home = '/usr/share/kibana',
  $kibana_path_config = '/etc/kibana',

  $kibana_settings = {},
  $saml_realm = undef,
) {

  # install package
  package { $kibana_package:
    ensure => $kibana_version,
    name   => $kibana_package,
  }

  file { ["${kibana_path_home}/optimize", "${kibana_path_home}/plugins"]:
    recurse => true,
    owner   => $kibana_user,
    group   => $kibana_group,
    require => Package[$kibana_package],
  }

  file { 'Configure kibana.yml':
    path    => "${kibana_path_config}/kibana.yml",
    owner   => $kibana_user,
    group   => $kibana_group,
    mode    => '0644',
    notify  => [ Service[$kibana_service], Exec['Waiting for elasticsearch...'] ],
    content => template('wazuh/kibana_yml.erb'),
  }

  service { $kibana_service:
    ensure     => running,
    enable     => true,
    hasrestart => true,
  } 

  if ($facts['kibana_plugin_wazuh'] != undef and
      $facts['kibana_plugin_wazuh']['version'] != $kibana_wazuh_version) or ($kibana_app_reinstall == true) {

    file {'Removing old Wazuh Kibana Plugin...':
      ensure  => absent,
      path    => "${kibana_path_home}/plugins/wazuh",
      recurse => true,
      purge   => true,
      force   => true,
      notify  => Service[$kibana_service],
      before  => Exec['kibana-plugin install'],
    }
  }

  exec {'kibana-plugin install':
    path        => '/usr/bin',
    command     => "sudo -u ${kibana_user} ${kibana_path_home}/bin/kibana-plugin install \"${kibana_app_url}\"",
    environment => ["NODE_OPTIONS=\"${kibana_app_node_options}\""],
    creates     => "${kibana_path_home}/plugins/wazuh/package.json",
    notify      => Service[$kibana_service],
    require     => File["${kibana_path_home}/optimize"],
  } ->

  file { "${kibana_path_home}/plugins/wazuh/wazuh.yml":
    owner   => $kibana_user,
    group   => $kibana_group,
    mode    => '0644',
    content => template('wazuh/wazuh_yml.erb'),
    notify  => Service[$kibana_service],
    require => Exec['kibana-plugin install'],
  }

  exec {'Waiting for elasticsearch...':
    path        => '/usr/bin',
    command     => "curl -s -XGET ${kibana_elasticsearch_proto}://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",
    tries       => 100,
    try_sleep   => 3,
    refreshonly => true,
  } ->

  exec {'Removing .wazuh index...':
    path    => '/usr/bin',
    command => "curl -s -XDELETE -sL -I 'http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}/.wazuh' -o /dev/null",
    onlyif  => "curl -s -XGET -sLf -I 'http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}/.wazuh' -o /dev/null",
    notify  => Service[$kibana_service],
  }


}
