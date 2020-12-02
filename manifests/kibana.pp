# Wazuh App Copyright (C) 2020 Wazuh Inc. (License GPLv2)
# Setup for Kibana
class wazuh::kibana (
  $kibana_package = 'kibana',
  $kibana_service = 'kibana',
  $kibana_version = '7.9.3',
  $kibana_wazuh_version = '4.0.3',
  $kibana_elasticsearch_ip = 'localhost',
  $kibana_elasticsearch_port = '9200',

  $kibana_server_port = '5601',
  $kibana_server_host = '0.0.0.0',
  $kibana_elasticsearch_server_hosts ="http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",

  # app variables
  $kibana_app_url = "https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-${kibana_app_version}-1.zip",
  $kibana_app_version = "${kibana_wazuh_version}_${$kibana_version}",
  $kibana_app_reinstall = false,

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

) {

  # install package
  package { $kibana_package:
    ensure => $kibana_version,
    name   => $kibana_package,
  }

  file { 'Configure kibana.yml':
    path    => "${kibana_path_config}/kibana.yml",
    owner   => $kibana_user,
    group   => $kibana_group,
    mode    => '0644',
    notify  => Service[$kibana_service],
    content => template('wazuh/kibana_yml.erb'),
  }

  service { $kibana_service:
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  exec {'Waiting for elasticsearch...':
    path      => '/usr/bin',
    command   => "curl -s -XGET http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}",
    tries     => 100,
    try_sleep => 3,
  }

  exec {'kibana-plugin install':
    path    => '/usr/bin',
    command => "sudo -u ${kibana_user} ${kibana_path_home}/bin/kibana-plugin install ${kibana_app_url}",
    creates => "${kibana_path_home}/plugins/wazuh/package.json",
    notify  => Service[$kibana_service],
  }

  exec {'Removing .wazuh index...':
    path    => '/usr/bin',
    command => "curl -s -XDELETE -sL -I 'http://${kibana_elasticsearch_ip}:${kibana_elasticsearch_port}/.wazuh' -o /dev/null",
    notify  => Service[$kibana_service],
  }

  file { "${kibana_path_home}/plugins/wazuh/wazuh.yml":
    owner   => $kibana_user,
    group   => $kibana_group,
    mode    => '0644',
    content => template('wazuh/wazuh_yml.erb'),
    notify  => Service[$kibana_service]
  }

  file { ["${kibana_path_home}/optimize", "${kibana_path_home}/plugins"]:
  recurse => true,
  owner   => $kibana_user,
  group   => $kibana_group,
  require => Package[$kibana_package],
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

}
