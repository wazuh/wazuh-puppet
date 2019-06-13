# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Paramas file
class wazuh::params_manager {
  case $::kernel {
    'Linux': {

    # Versions  

      $server_package_version             =  '3.9.1-1'

    # Ossec.conf generation parameters
      
      $rootcheck_configure                = true
      $wodle_openscap_configure           = true
      $wodle_ciscat_configure             = true
      $wodle_osquery_configure            = true
      $wodle_syscollector_configure       = true
      $wodle_vulnerability_detector_configure = true
      $sca_configure                      = true
      $syscheck_configure                 = true
      $command_configure                  = true
      $localfile_configure                = true
      $ruleset_configure                  = true
      $auth_configure                     = true
      $cluster_configure                  = true
      
      ### Ossec.conf blocks

      $ossec_white_list                    = ["127.0.0.1","^localhost.localdomain$","10.0.0.2"]

      ## Email notifications

      $smtp_server                         = undef
      $ossec_emailto                       = []
      $ossec_emailfrom                     = "wazuh@${::domain}"
      $ossec_emailnotification             = false
      $ossec_email_maxperhour              = '12'
      $ossec_email_idsname                 = undef
      $ossec_email_alert_level             = 12

      ## Rootcheck

      $ossec_rootcheck_disabled            = true
      $ossec_rootcheck_check_files         = "yes"
      $ossec_rootcheck_check_trojans       = "yes"
      $ossec_rootcheck_check_dev           = "yes"
      $ossec_rootcheck_check_sys           = "yes"
      $ossec_rootcheck_check_pids          = "yes"
      $ossec_rootcheck_check_ports         = "yes"
      $ossec_rootcheck_check_if            = "yes"
      $ossec_rootcheck_frequency           = 43200
      $ossec_rootcheck_rootkit_files       = "/var/ossec/etc/rootcheck/rootkit_files.txt"
      $ossec_rootcheck_rootkit_trojans     = "/var/ossec/etc/rootcheck/rootkit_trojans.txt"
      $ossec_rootcheck_skip_nfs            = "yes"
      
      ## Wodles

      #openscap
      $wodle_openscap_disabled             = true
      $wodle_openscap_timeout              = "1800"
      $wodle_openscap_interval             = "1d"
      $wodle_openscap_scan_on_start        = "yes"
      
      #cis-cat
      $wodle_ciscat_disabled               = true
      $wodle_ciscat_timeout                = "1800"
      $wodle_ciscat_interval               = "1d"
      $wodle_ciscat_scan_on_start          = "yes"
      $wodle_ciscat_java_path              = "wodles/java"
      $wodle_ciscat_ciscat_path            = "wodles/ciscat"

      #osquery

      $wodle_osquery_disabled             = true
      $wodle_osquery_run_daemon           = "yes"
      $wodle_osquery_log_path             = "/var/log/osquery/osqueryd.results.log"
      $wodle_osquery_config_path          = "/etc/osquery/osquery.conf"
      $wodle_osquery_add_labels           = "yes"

      #syscollector
      $wodle_syscollector_disabled        = true
      $wodle_syscollector_interval        = "1h"
      $wodle_syscollector_scan_on_start   = "yes"
      $wodle_syscollector_hardware        = "yes"
      $wodle_syscollector_os              = "yes"
      $wodle_syscollector_network         = "yes"
      $wodle_syscollector_packages        = "yes"
      $wodle_syscollector_ports           = "yes"
      $wodle_syscollector_processes       = "yes"

      #vulnerability-detector

      $wodle_vulnerability_detector_disabled             = true
      $wodle_vulnerability_detector_interval             = "5m"
      $wodle_vulnerability_detector_ignore_time          = "6h"
      $wodle_vulnerability_detector_run_on_start         = "yes"
      $wodle_vulnerability_detector_ubuntu_disabled      = "yes"
      $wodle_vulnerability_detector_ubuntu_update        = "1h"
      $wodle_vulnerability_detector_redhat_disable       = "yes"
      $wodle_vulnerability_detector_redhat_update_from   = "2010"
      $wodle_vulnerability_detector_redhat_update        = "1h"
      $wodle_vulnerability_detector_debian_9_disable     = "yes"
      $wodle_vulnerability_detector_debian_9_update      = "1h"

      # syslog

      $syslog_output                       = false
      $syslog_output_level                 = 2
      $syslog_output_port                  = 514
      $syslog_output_server                = undef
      $syslog_output_format                = undef

      # Authd configuration

      $ossec_auth_disabled                 = "no"
      $ossec_auth_port                     = 1515
      $ossec_auth_use_source_ip            = "yes"
      $ossec_auth_force_insert             = "yes"
      $ossec_auth_force_time               = 0
      $ossec_auth_purgue                   = "yes"
      $ossec_auth_use_password             = "no"
      $ossec_auth_limit_maxagents          = "yes"
      $ossec_auth_ciphers                  = "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
      $ossec_auth_ssl_verify_host          = "no"
      $ossec_auth_ssl_manager_cert         = "/var/ossec/etc/sslmanager.cert"
      $ossec_auth_ssl_manager_key          = "/var/ossec/etc/sslmanager.key"
      $ossec_auth_ssl_auto_negotiate       = "no"

      #----- End of ossec.conf parameters -------

      ### Wazuh-API

      $api_package_version                 = 'installed'
      $api_config_params                   = $::wazuh::params_manager::api_config_params
      $api_config_template                 = 'wazuh/api/config.js.erb'
      $install_wazuh_api                   = false
      $wazuh_api_enable_https              = false
      $wazuh_api_server_crt                = undef
      $wazuh_api_server_key                = undef


      $ossec_ignorepaths                   = []
      $ossec_ignorepaths_regex             = []
      $ossec_scanpaths                     = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'yes', 'realtime' => 'yes'} ]
    
      

      $ossec_syscheck_frequency            = 79200
      $ossec_auto_ignore                   = 'yes'
      $ossec_prefilter                     = false
      
      $ossec_server_port                   = '1514'
      $ossec_server_protocol               = 'udp'
      $ossec_integratord_enabled           = false

      
      
      $manage_repos                        = true
      $manage_epel_repo                    = true
      $manage_client_keys                  = 'authd'
      $agent_auth_password                 = undef
      $ar_repeated_offenders               = ''

      $local_decoder_template              = 'wazuh/local_decoder.xml.erb'
      $decoder_exclude                     = []
      $local_rules_template                = 'wazuh/local_rules.xml.erb'
      $rule_exclude                        = []
      $shared_agent_template               = 'wazuh/ossec_shared_agent.conf.erb'
      
      $wazuh_manager_verify_manager_ssl    = false
      $wazuh_manager_server_crt            = undef
      $wazuh_manager_server_key            = undef


      ## Wazuh config folders and modes

      $config_file = '/var/ossec/etc/ossec.conf'
      $shared_agent_config_file = '/var/ossec/etc/shared/agent.conf'

      $config_mode = '0640'
      $config_owner = 'root'
      $config_group = 'ossec'

      $keys_file = '/var/ossec/etc/client.keys'
      $keys_mode = '0640'
      $keys_owner = 'root'
      $keys_group = 'ossec'

      $manage_firewall = false
      $authd_pass_file = '/var/ossec/etc/authd.pass'

      $validate_cmd_conf = '/var/ossec/bin/verify-agent-conf -f %'

      $processlist_file = '/var/ossec/bin/.process_list'
      $processlist_mode = '0640'
      $processlist_owner = 'root'
      $processlist_group = 'ossec'


      case $::osfamily {
        'Debian': {

          $agent_service  = 'wazuh-agent'
          $agent_package  = 'wazuh-agent'
          $service_has_status  = false
          $ossec_service_provider = undef
          $api_service_provider = undef
          $default_local_files = [
            {  'location' => '/var/log/syslog' , 'log_format' => 'syslog'},
            {  'location' => '/var/log/kern.log' , 'log_format' => 'syslog'},
            {  'location' => '/var/log/auth.log' , 'log_format' => 'syslog'},
            {  'location' => '/var/log/dpkg.log', 'log_format' => 'syslog'},
            {  'location' => '/var/ossec/logs/active-responses.log', 'log_format' => 'syslog'},
          ]
          case $::lsbdistcodename {
            'xenial': {
              $server_service = 'wazuh-manager'
              $server_package = 'wazuh-manager'
              $api_service = 'wazuh-api'
              $api_package = 'wazuh-api'
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
              $api_service = 'wazuh-api'
              $api_package = 'wazuh-api'
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
            /^(wheezy|stretch|sid|precise|trusty|vivid|wily|xenial|bionic)$/: {
              $server_service = 'wazuh-manager'
              $server_package = 'wazuh-manager'
              $api_service = 'wazuh-api'
              $api_package = 'wazuh-api'
              $wodle_openscap_content = undef
            }
        default: {
          fail("Module ${module_name} is not supported on ${::operatingsystem}")
        }
          }

        }
        'RedHat': {

          $agent_service  = 'wazuh-agent'
          $agent_package  = 'wazuh-agent'
          $server_service = 'wazuh-manager'
          $server_package = 'wazuh-manager'
          $api_service = 'wazuh-api'
          $api_package = 'wazuh-api'
          $service_has_status  = true

          $default_local_files =[
              {  'location' => '/var/log/audit/audit.log' , 'log_format' => 'audit'},
              {  'location' => '/var/ossec/logs/active-responses.log' , 'log_format' => 'syslog'},
              {  'location' => '/var/log/messages', 'log_format' => 'syslog'},
              {  'location' => '/var/log/secure' , 'log_format' => 'syslog'},
              {  'location' => '/var/log/maillog' , 'log_format' => 'apache'},
          ]
          case $::operatingsystem {
            'Amazon': {
              # Amazon is based on Centos-6 with some improvements
              # taken from RHEL-7 but uses SysV-Init, not Systemd.
              # Probably best to leave this undef until we can
              # write/find a release-specific file.
              $wodle_openscap_content = undef
            }
            'CentOS': {
              if ( $::operatingsystemrelease =~ /^6.*/ ) {
                $ossec_service_provider = 'redhat'
                $api_service_provider = 'redhat'
                $wodle_openscap_content = {
                  'ssg-centos-6-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_server',]
                  }
                }
              }
              if ( $::operatingsystemrelease =~ /^7.*/ ) {
                $ossec_service_provider = 'systemd'
                $api_service_provider = 'systemd'
                $wodle_openscap_content = {
                  'ssg-centos-7-ds.xml' => {
                    'type' => 'xccdf',
                    profiles => ['xccdf_org.ssgproject.content_profile_pci-dss', 'xccdf_org.ssgproject.content_profile_common',]
                  }
                }
              }
            }
            /^(RedHat|OracleLinux)$/: {
              if ( $::operatingsystemrelease =~ /^6.*/ ) {
                $ossec_service_provider = 'redhat'
                $api_service_provider = 'redhat'
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
                $ossec_service_provider = 'systemd'
                $api_service_provider = 'systemd'
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
                $ossec_service_provider = 'redhat'
                $api_service_provider = 'redhat'
                $wodle_openscap_content = {
                  'ssg-fedora-ds.xml' => {
                    'type' => 'xccdf',
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

      $manage_firewall = false

      $keys_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/client.keys'), '\\\\', '/')
      $keys_mode = '0440'
      $keys_owner = 'Administrator'
      $keys_group = 'Administrators'

      $agent_service  = 'OssecSvc'
      $agent_package  = 'Wazuh Agent 3.9.1'
      $server_service = ''
      $server_package = ''
      $api_service = ''
      $api_package = ''
      $service_has_status  = true

      # TODO
      $validate_cmd_conf = undef
      # Pushed by shared agent config now
      $default_local_files =  [
        {'location' => 'Security' , 'log_format' => 'eventchannel', 'query' => 'Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907]'},
        {'location' => 'System' , 'log_format' =>  'eventlog'  },
        {'location' => 'active-response\active-responses.log' , 'log_format' =>  'syslog'  },
      ]

    }
  default: { fail('This ossec module has not been tested on your distribution') }
  }
}
