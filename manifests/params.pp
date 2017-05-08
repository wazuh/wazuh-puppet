# Paramas file
class wazuh::params {
  case $::kernel {
    'Linux': {

      $config_file = '/var/ossec/etc/ossec.conf'
      $shared_agent_config_file = '/var/ossec/etc/shared/agent.conf'

      $config_mode = '0440'
      $config_owner = 'root'
      $config_group = 'ossec'

      $keys_file = '/var/ossec/etc/client.keys'
      $keys_mode = '0440'
      $keys_owner = 'root'
      $keys_group = 'ossec'

      $authd_pass_file = '/var/ossec/etc/authd.pass'

      $validate_cmd_conf = "/var/ossec/bin/verify-agent-conf -f %"

      $processlist_file = '/var/ossec/bin/.process_list'
      $processlist_mode = '0440'
      $processlist_owner = 'root'
      $processlist_group = 'ossec'

      case $::osfamily {
        'Debian': {

          $agent_service  = 'wazuh-agent'
          $agent_package  = 'wazuh-agent'
          $service_has_status  = false
          $ossec_service_provider = undef

          $default_local_files = {
            '/var/log/syslog'                      => 'syslog',
            '/var/log/kern.log'                    => 'syslog',
            '/var/log/auth.log'                    => 'syslog',
            '/var/log/mail.log'                    => 'syslog',
            '/var/log/dpkg.log'                    => 'syslog',
            '/var/ossec/logs/active-responses.log' => 'syslog',
          }

          case $::lsbdistcodename {
            'xenial': {
              $server_service = 'wazuh-manager'
              $server_package = 'wazuh-manager'
              $wodle_openscap_content = {
                'ssg-ubuntu-1604-ds.xml' => {
                  'type' => 'xccdf',
                  profiles => ['xccdf_org.ssgproject.content_profile_common'],
                },
              }
            }
            'jessie': {
              $server_service = 'wazuh-manager'
              $server_package = 'wazuh-manager'
              $wodle_openscap_content = {
                'ssg-debian-8-ds.xml' => {
                  'type' => 'xccdf',
                  profiles => ['xccdf_org.ssgproject.content_profile_common'],
                },
                'cve-debian-oval.xml' => {
                  'type' => 'oval',
                }
              }
            }
            /^(wheezy|stretch|sid|precise|trusty|vivid|wily|xenial)$/: {
              $server_service = 'wazuh-manager'
              $server_package = 'wazuh-manager'
              $wodle_openscap_content = undef
            }
        default: {
          fail("Module ${module_name} is not supported on ${::operatingsystem}")
        }
          }

        }
        'Linux', 'RedHat': {

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
          case $::operatingsystem {
            'CentOS': {
              if ( $::operatingsystemrelease =~ /^6.*/ ) {
                $wodle_openscap_content = {
                  'ssg-centos-6-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_server',]
                }
              }
              }
              if ( $::operatingsystemrelease =~ /^7.*/ ) {
                $wodle_openscap_content = {
                  'ssg-centos-7-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_server',]
                }
              }
              }
            }
            'Redhat': {
              if ( $::operatingsystemrelease =~ /^6.*/ ) {
                $wodle_openscap_content = {
                  'ssg-rhel-6-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_server',]
                },
                'cve-redhat-6-ds.xml' => {
                'type' => 'xccdf',
                  }
              }
              }
              if ( $::operatingsystemrelease =~ /^7.*/ ) {
                $wodle_openscap_content = {
                  'ssg-rhel-7-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_common',]
                },
                'cve-redhat-7-ds.xml' => {
                'type' => 'xccdf',
                  }
              }
              }
            }
            'Fedora': {
              if ( $::operatingsystemrelease =~ /^(23|24|25).*/ ) {
                $wodle_openscap_content = {
                  'ssg-fedora-ds.xml' => {
                    type => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_standard', 'xccdf_org.ssgproject.content_profile_common',]
                },
              }
              }
            }
            default: { fail('This ossec module has not been tested on your distribution') }
            }
          }
        default: { fail('This ossec module has not been tested on your distribution') }
        } 
  }
    'windows': {
      $config_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/ossec.conf'), '\\\\', '/')
      $shared_agent_config_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/shared/agent.conf'), '\\\\', '/')
      $config_owner = 'Administrator'
      $config_group = 'Administrators'

      $keys_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/client.keys'), '\\\\', '/')
      $keys_mode = '0440'
      $keys_owner = 'Administrator'
      $keys_group = 'Administrators'

      $agent_service  = 'OssecSvc'
      $agent_package  = 'Wazuh Agent 2.0'
      $server_service = ''
      $server_package = ''
      $service_has_status  = true

      # TODO
      $validate_cmd_conf = undef
      # Pushed by shared agent config now
      $default_local_files = {}
    }
  default: { fail('This ossec module has not been tested on your distribution') }
  }
}
