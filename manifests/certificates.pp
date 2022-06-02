# Copyright (C) 2015, Wazuh Inc.
# Wazuh repository installation
class wazuh::certificates (
  $wazuh_repository = 'packages.wazuh.com',
  $wazuh_version = '4.4',
) {

  $certs_path = '/tmp/wazuh-certificates'

  $path_exists = find_file($certs_path)

  unless $path_exists {
    file { 'Configure config.yml':
        owner   => 'root',
        path    => '/tmp/config.yml',
        group   => 'root',
        mode    => '0644',
        content => template('wazuh/wazuh_config_yml.erb'),
    }

    exec { 'Create Wazuh Certificates':
        path    => '/usr/bin:/bin',
        command => "curl -so /tmp/wazuh-certs-tool.sh 'https://${wazuh_repository}/${wazuh_version}/wazuh-certs-tool.sh'\
                && chmod 744 /tmp/wazuh-certs-tool.sh\
                && bash /tmp/wazuh-certs-tool.sh --all",

    }
  }

}

