class wazuh::params {
  case $::kernel {
    'Linux': {

      $config_file = '/var/ossec/etc/ossec.conf'
      $config_mode = '0440'
      $config_owner = 'root'
      $config_group = 'ossec'

      $keys_file = '/var/ossec/etc/client.keys'
      $keys_mode = '0440'
      $keys_owner = 'root'
      $keys_group = 'ossec'

      $processlist_file = '/var/ossec/bin/.process_list'
      $processlist_mode = '0440'
      $processlist_owner = 'root'
      $processlist_group = 'ossec'

      case $::osfamily {
        'Redhat': {

          $agent_service  = 'wazuh-agent'

          $agent_package  = 'wazuh-agent'

          $server_service = 'wazuh-manager'

          $server_package = 'wazuh-manager'

          $service_has_status  = true

          $ossec_service_provider = 'redhat'

          $default_local_files = {
            '/var/log/messages'         => 'syslog',
            '/var/log/secure'           => 'syslog',
            '/var/log/maillog'          => 'syslog',
            '/var/log/yum.log'          => 'syslog',
            '/var/log/httpd/access_log' => 'apache',
            '/var/log/httpd/error_log'  => 'apache'
          }

        }
      }
    }
    'windows': {
      $config_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/ossec.conf'), '\\\\', '/')
      $config_owner = 'Administrator'
      $config_group = 'Administrators'

      $keys_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/client.keys'), '\\\\', '/')
      $keys_mode = '0440'
      $keys_owner = 'Administrator'
      $keys_group = 'Administrators'

      $agent_service  = 'OssecSvc'

      $agent_package  = 'WAZUH HIDS'

      $server_service = ''

      $server_package = ''

      $service_has_status  = true

      # Pushed by shared agent config now
      $default_local_files = {}

    }
    default: { fail('This ossec module has not been tested on your distribution') }
  }
}
