# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Wazuh-Agent configuration parameters
class wazuh::params_agent {
  case $::kernel {
    'Linux': {

# Versions

      $agent_package_version             = '3.10.2-1'
      $agent_package_name                = 'wazuh-agent'
      $agent_service_name                = 'wazuh-agent'

    # Authd Registration options

      $manage_client_keys                = 'yes'  # Enable/Disable agent registration
      $agent_name                        = undef
      $agent_group                       = undef
      $wazuh_agent_cert                  = undef
      $wazuh_agent_key                   = undef
      $wazuh_agent_cert_path             = undef
      $wazuh_agent_key_path              = undef
      $agent_auth_password               = undef
      $wazuh_manager_root_ca_pem         = undef

      $wazuh_manager_root_ca_pem_path    = undef

    ## Wazuh config folders and modes

      $config_file                       = '/var/ossec/etc/ossec.conf'
      $shared_agent_config_file          = '/var/ossec/etc/shared/agent.conf'

      $config_mode                       = '0640'
      $config_owner                      = 'root'
      $config_group                      = 'ossec'

      $keys_file                         = '/var/ossec/etc/client.keys'
      $keys_mode                         = '0640'
      $keys_owner                        = 'root'
      $keys_group                        = 'ossec'

      $manage_firewall                   = false
      $authd_pass_file                   = '/var/ossec/etc/authd.pass'

      $validate_cmd_conf                 = '/var/ossec/bin/verify-agent-conf -f %'

      $processlist_file                  = '/var/ossec/bin/.process_list'
      $processlist_mode                  = '0640'
      $processlist_owner                 = 'root'
      $processlist_group                 = 'ossec'

    # ossec.conf generation parameters

      ## Ossec.conf generation variables

      $configure_rootcheck               = true
      $configure_wodle_openscap          = true
      $configure_wodle_cis_cat           = true
      $configure_wodle_osquery           = true
      $configure_wodle_syscollector      = true
      $configure_sca                     = true
      $configure_syscheck                = true
      $configure_localfile               = true
      $configure_active_response         = true


    # ossec.conf templates paths
      $ossec_conf_template               = 'wazuh/wazuh_agent.conf.erb'
      $ossec_rootcheck_template          = 'wazuh/fragments/_rootcheck.erb'
      $ossec_wodle_openscap_template     = 'wazuh/fragments/_wodle_openscap.erb'
      $ossec_wodle_cis_cat_template      = 'wazuh/fragments/_wodle_cis_cat.erb'
      $ossec_wodle_osquery_template      = 'wazuh/fragments/_wodle_osquery.erb'
      $ossec_wodle_syscollector_template = 'wazuh/fragments/_wodle_syscollector.erb'
      $ossec_sca_template                = 'wazuh/fragments/_sca.erb'
      $ossec_syscheck_template           = 'wazuh/fragments/_syscheck.erb'
      $ossec_localfile_template          = 'wazuh/fragments/_localfile.erb'
      $ossec_ruleset                     = 'wazuh/fragments/_ruleset.erb'
      $ossec_auth                        = 'wazuh/fragments/_auth.erb'
      $ossec_cluster                     = 'wazuh/fragments/_cluster.erb'
      $ossec_active_response_template    = 'wazuh/fragments/_default_activeresponse.erb'

      ### Ossec.conf blocks

      ## Server block configuration

      $wazuh_register_endpoint           = undef
      $wazuh_reporting_endpoint          = undef
      $ossec_port                        = '1514'
      $ossec_protocol                    = 'udp'
      $ossec_notify_time                 = 10
      $ossec_time_reconnect              = 60
      $ossec_auto_restart                = 'yes'
      $ossec_crypto_method               = 'aes'

      $client_buffer_queue_size          = 5000
      $client_buffer_events_per_second   = 500

      # Rootcheck

      $ossec_rootcheck_disabled          = 'no'
      $ossec_rootcheck_check_files       = 'yes'
      $ossec_rootcheck_check_trojans     = 'yes'
      $ossec_rootcheck_check_dev         = 'yes'
      $ossec_rootcheck_check_sys         = 'yes'
      $ossec_rootcheck_check_pids        = 'yes'
      $ossec_rootcheck_check_ports       = 'yes'
      $ossec_rootcheck_check_if          = 'yes'
      $ossec_rootcheck_frequency         = 43200
      $ossec_rootcheck_rootkit_files     = '/var/ossec/etc/shared/rootkit_files.txt'
      $ossec_rootcheck_rootkit_trojans   = '/var/ossec/etc/shared/rootkit_trojans.txt'
      $ossec_rootcheck_skip_nfs          = 'yes'

    ## Wodles

      #openscap
      $wodle_openscap_disabled           = 'no'
      $wodle_openscap_timeout            = '1800'
      $wodle_openscap_interval           = '1d'
      $wodle_openscap_scan_on_start      = 'yes'

      #cis-cat
      $wodle_ciscat_disabled             = 'yes'
      $wodle_ciscat_timeout              = '1800'
      $wodle_ciscat_interval             = '1d'
      $wodle_ciscat_scan_on_start        = 'yes'
      $wodle_ciscat_java_path            = 'wodles/java'
      $wodle_ciscat_ciscat_path          = 'wodles/ciscat'

      #osquery

      $wodle_osquery_disabled            = 'yes'
      $wodle_osquery_run_daemon          = 'yes'
      $wodle_osquery_log_path            = '/var/log/osquery/osqueryd.results.log'
      $wodle_osquery_config_path         = '/etc/osquery/osquery.conf'
      $wodle_osquery_add_labels          = 'yes'

      #syscollector
      $wodle_syscollector_disabled       = true
      $wodle_syscollector_interval       = '1d'
      $wodle_syscollector_scan_on_start  = 'yes'
      $wodle_syscollector_hardware       = 'yes'
      $wodle_syscollector_os             = 'yes'
      $wodle_syscollector_network        = 'yes'
      $wodle_syscollector_packages       = 'yes'
      $wodle_syscollector_ports          = 'yes'
      $wodle_syscollector_processes      = 'yes'

      # localfile
      $ossec_local_files                 = $::wazuh::params_agent::default_local_files

      #syscheck
      $ossec_syscheck_disabled           = 'no'
      $ossec_syscheck_frequency          = '43200'
      $ossec_syscheck_scan_on_start      = 'yes'
      $ossec_syscheck_alert_new_files    = undef
      $ossec_syscheck_auto_ignore        = undef
      $ossec_syscheck_directories_1      = '/etc,/usr/bin,/usr/sbin'
      $ossec_syscheck_directories_2      = '/bin,/sbin,/boot'
      $ossec_syscheck_ignore_list        = ['/etc/mtab',
                                              '/etc/hosts.deny',
                                              '/etc/mail/statistics',
                                              '/etc/random-seed',
                                              '/etc/random.seed',
                                              '/etc/adjtime',
                                              '/etc/httpd/logs',
                                              '/etc/utmpx',
                                              '/etc/wtmpx',
                                              '/etc/cups/certs',
                                              '/etc/dumpdates',
                                              '/etc/svc/volatile',
                                              '/sys/kernel/security',
                                              '/sys/kernel/debug',
                                              '/dev/core',
                                            ]
      $ossec_syscheck_ignore_type_1      = '^/proc'
      $ossec_syscheck_ignore_type_2      = ".log$|.swp$"


      $ossec_syscheck_nodiff             = '/etc/ssl/private.key'
      $ossec_syscheck_skip_nfs           = 'yes'


      # others

      $selinux                         = false

      $manage_repo                     = true

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
            {  'location' => '/var/log/messages' , 'log_format' => 'syslog'},
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
                },'cve-ubuntu-xenial-oval.xml' => {
                  'type' => 'oval'
                }
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
                'cve-debian-8-oval.xml' => {
                  'type' => 'oval',
                }
              }
            }
            'stretch': {
              $server_service = 'wazuh-manager'
              $server_package = 'wazuh-manager'
              $api_service = 'wazuh-api'
              $api_package = 'wazuh-api'
              $wodle_openscap_content = {
                'ssg-debian-9-ds.xml' => {
                  'type' => 'xccdf',
                  profiles => ['xccdf_org.ssgproject.content_profile_common'],
                },
                'cve-debian-9-oval.xml' => {
                  'type' => 'oval',
                }
              }
            }
            /^(wheezy|sid|precise|trusty|vivid|wily|xenial|bionic)$/: {
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
              {  'location' => '/var/log/maillog' , 'log_format' => 'syslog'},
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
      $download_path = 'C:/'
      $manage_firewall = false

      $keys_file = regsubst(sprintf('c:/Program Files (x86)/ossec-agent/client.keys'), '\\\\', '/')
      $keys_mode = '0440'
      $keys_owner = 'Administrator'
      $keys_group = 'Administrators'

      $agent_service  = 'OssecSvc'
      $agent_package  = 'Wazuh Agent 3.10.2'
      $server_service = ''
      $server_package = ''
      $api_service = ''
      $api_package = ''
      $service_has_status  = true

      # TODO
      $validate_cmd_conf = undef
      # Pushed by shared agent config now
      $default_local_files =  [
        {'location' => 'Security' , 'log_format' => 'eventchannel',
        'query' => 'Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658\
        and EventID != 4663 and EventID != 4660 and EventID != 4670 and EventID != 4690 and EventID!= 4703 and EventID != 4907]'},
        {'location' => 'System' , 'log_format' =>  'eventlog'  },
        {'location' => 'active-response\active-responses.log' , 'log_format' =>  'syslog'  },
      ]

    }
  default: { fail('This ossec module has not been tested on your distribution') }
  }
}
