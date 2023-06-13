# Copyright (C) 2015, Wazuh Inc.
# Paramas file
class wazuh::params_manager {
  case $::kernel {
    'Linux': {

    # Installation
      $server_package_version                          = '4.4.4-1'

      $manage_repos                                    = true
      $manage_firewall                                 = false

    ### Ossec.conf blocks

      ## Global
      $ossec_logall                                    = 'no'
      $ossec_logall_json                               = 'no'
      $ossec_emailnotification                         = false
      $ossec_emailto                                   = ['recipient@example.wazuh.com']
      $ossec_smtp_server                               = 'smtp.example.wazuh.com'
      $ossec_emailfrom                                 = 'ossecm@example.wazuh.com'
      $ossec_email_maxperhour                          = 12
      $ossec_email_idsname                             = undef
      $ossec_email_log_source                          = 'alerts.log'
      $ossec_white_list                                = ['127.0.0.1','^localhost.localdomain$','10.0.0.2']
      $ossec_alert_level                               = 3
      $ossec_email_alert_level                         = 12
      $ossec_remote_connection                         = 'secure'
      $ossec_remote_port                               = 1514
      $ossec_remote_protocol                           = 'tcp'
      $ossec_remote_local_ip                           = undef
      $ossec_remote_allowed_ips                        = undef
      $ossec_remote_queue_size                         = 131072

    # ossec.conf generation parameters

      $configure_rootcheck                             = true
      $configure_wodle_openscap                        = true
      $configure_wodle_cis_cat                         = true
      $configure_wodle_osquery                         = true
      $configure_wodle_syscollector                    = true
      $configure_wodle_docker_listener                 = false
      $configure_vulnerability_detector                = true
      $configure_sca                                   = true
      $configure_syscheck                              = true
      $configure_command                               = true
      $configure_localfile                             = true
      $configure_ruleset                               = true
      $configure_auth                                  = true
      $configure_cluster                               = true
      $configure_active_response                       = false


    # ossec.conf templates paths
      $ossec_manager_template                          = 'wazuh/wazuh_manager.conf.erb'
      $ossec_rootcheck_template                        = 'wazuh/fragments/_rootcheck.erb'
      $ossec_wodle_openscap_template                   = 'wazuh/fragments/_wodle_openscap.erb'
      $ossec_wodle_cis_cat_template                    = 'wazuh/fragments/_wodle_cis_cat.erb'
      $ossec_wodle_osquery_template                    = 'wazuh/fragments/_wodle_osquery.erb'
      $ossec_wodle_syscollector_template               = 'wazuh/fragments/_wodle_syscollector.erb'
      $ossec_wodle_docker_listener_template            = 'wazuh/fragments/_wodle_docker_listener.erb'
      $ossec_vulnerability_detector_template           = 'wazuh/fragments/_vulnerability_detector.erb'
      $ossec_sca_template                              = 'wazuh/fragments/_sca.erb'
      $ossec_syscheck_template                         = 'wazuh/fragments/_syscheck.erb'
      $ossec_default_commands_template                 = 'wazuh/default_commands.erb'
      $ossec_localfile_template                        = 'wazuh/fragments/_localfile.erb'
      $ossec_ruleset_template                          = 'wazuh/fragments/_ruleset.erb'
      $ossec_auth_template                             = 'wazuh/fragments/_auth.erb'
      $ossec_cluster_template                          = 'wazuh/fragments/_cluster.erb'
      $ossec_active_response_template                  = 'wazuh/fragments/_default_activeresponse.erb'
      $ossec_syslog_output_template                    = 'wazuh/fragments/_syslog_output.erb'

      ## Rootcheck

      $ossec_rootcheck_disabled                        = 'no'
      $ossec_rootcheck_check_files                     = 'yes'
      $ossec_rootcheck_check_trojans                   = 'yes'
      $ossec_rootcheck_check_dev                       = 'yes'
      $ossec_rootcheck_check_sys                       = 'yes'
      $ossec_rootcheck_check_pids                      = 'yes'
      $ossec_rootcheck_check_ports                     = 'yes'
      $ossec_rootcheck_check_if                        = 'yes'
      $ossec_rootcheck_frequency                       = 43200
      $ossec_rootcheck_ignore_list                     = []
      $ossec_rootcheck_ignore_sregex_list              = []
      $ossec_rootcheck_rootkit_files                   = '/var/ossec/etc/rootcheck/rootkit_files.txt'
      $ossec_rootcheck_rootkit_trojans                 = '/var/ossec/etc/rootcheck/rootkit_trojans.txt'
      $ossec_rootcheck_skip_nfs                        = 'yes'
      $ossec_rootcheck_system_audit                    = []

      # SCA

      ## Amazon
      $sca_amazon_enabled = 'yes'
      $sca_amazon_scan_on_start = 'yes'
      $sca_amazon_interval = '12h'
      $sca_amazon_skip_nfs = 'yes'
      $sca_amazon_policies = []

      ## RHEL
      $sca_rhel_enabled = 'yes'
      $sca_rhel_scan_on_start = 'yes'
      $sca_rhel_interval = '12h'
      $sca_rhel_skip_nfs = 'yes'
      $sca_rhel_policies = []

      ## <else>
      $sca_else_enabled = 'yes'
      $sca_else_scan_on_start = 'yes'
      $sca_else_interval = '12h'
      $sca_else_skip_nfs = 'yes'
      $sca_else_policies = []


      ## Wodles

      #openscap
      $wodle_openscap_disabled                         = 'yes'
      $wodle_openscap_timeout                          = '1800'
      $wodle_openscap_interval                         = '1d'
      $wodle_openscap_scan_on_start                    = 'yes'

      #cis-cat
      $wodle_ciscat_disabled                           = 'yes'
      $wodle_ciscat_timeout                            = '1800'
      $wodle_ciscat_interval                           = '1d'
      $wodle_ciscat_scan_on_start                      = 'yes'
      $wodle_ciscat_java_path                          = 'wodles/java'
      $wodle_ciscat_ciscat_path                        = 'wodles/ciscat'

      #osquery

      $wodle_osquery_disabled                          = 'yes'
      $wodle_osquery_run_daemon                        = 'yes'
      $wodle_osquery_log_path                          = '/var/log/osquery/osqueryd.results.log'
      $wodle_osquery_config_path                       = '/etc/osquery/osquery.conf'
      $wodle_osquery_add_labels                        = 'yes'

      #syscollector
      $wodle_syscollector_disabled                     = 'no'
      $wodle_syscollector_interval                     = '1h'
      $wodle_syscollector_scan_on_start                = 'yes'
      $wodle_syscollector_hardware                     = 'yes'
      $wodle_syscollector_os                           = 'yes'
      $wodle_syscollector_network                      = 'yes'
      $wodle_syscollector_packages                     = 'yes'
      $wodle_syscollector_ports                        = 'yes'
      $wodle_syscollector_processes                    = 'yes'

      #docker-listener
      $wodle_docker_listener_disabled                  = 'no'

      #active-response
      $active_response_command                         = 'firewall-drop'
      $active_response_location                        = 'local'
      $active_response_level                           = 9
      $active_response_agent_id                        = '001'
      $active_response_rules_id                        = [31153,31151]
      $active_response_timeout                         = 300
      $active_response_repeated_offenders              = ['30,60,120']

      #vulnerability-detector

      $vulnerability_detector_enabled                            = 'no'
      $vulnerability_detector_interval                           = '5m'
      $vulnerability_detector_min_full_scan_interval             = '6h'
      $vulnerability_detector_run_on_start                       = 'yes'

      $vulnerability_detector_provider_canonical                 = 'yes'
      $vulnerability_detector_provider_canonical_enabled         = 'no'
      $vulnerability_detector_provider_canonical_os              = ['trusty',
        'xenial',
        'bionic'
      ]
      $vulnerability_detector_provider_canonical_update_interval = '1h'


      $vulnerability_detector_provider_debian                 = 'yes'
      $vulnerability_detector_provider_debian_enabled         = 'no'
      $vulnerability_detector_provider_debian_os              = ['wheezy',
        'stretch',
        'jessie',
        'buster'
      ]
      $vulnerability_detector_provider_debian_update_interval = '1h'
      $vulnerability_detector_provider_redhat                    = 'yes'
      $vulnerability_detector_provider_redhat_enabled            = 'no'
      $vulnerability_detector_provider_redhat_os                 = ['5','6','7','8']
      $vulnerability_detector_provider_redhat_update_from_year   = '2010'
      $vulnerability_detector_provider_redhat_update_interval    = '1h'      # syslog


      $vulnerability_detector_provider_nvd                    = 'yes'
      $vulnerability_detector_provider_nvd_enabled            = 'no'
      $vulnerability_detector_provider_nvd_os                 = []
      $vulnerability_detector_provider_nvd_update_from_year   = '2010'
      $vulnerability_detector_provider_nvd_update_interval    = '1h'

      $vulnerability_detector_provider_arch                   = 'yes'
      $vulnerability_detector_provider_arch_enabled           = 'no'
      $vulnerability_detector_provider_arch_update_interval   = '1h'

      $vulnerability_detector_provider_alas                   = 'yes'
      $vulnerability_detector_provider_alas_enabled           = 'no'
      $vulnerability_detector_provider_alas_os              = ['amazon-linux',
      'amazon-linux-2'
      ]
      $vulnerability_detector_provider_alas_update_interval   = '1h'

      $vulnerability_detector_provider_msu                   = 'yes'
      $vulnerability_detector_provider_msu_enabled           = 'no'
      $vulnerability_detector_provider_msu_update_interval   = '1h'

      $syslog_output                                   = false
      $syslog_output_level                             = 2
      $syslog_output_port                              = 514
      $syslog_output_server                            = undef
      $syslog_output_format                            = undef

      # Authd configuration

      $ossec_auth_disabled                             = 'no'
      $ossec_auth_port                                 = 1515
      $ossec_auth_use_source_ip                        = 'yes'
      $ossec_auth_force_enabled                        = 'yes'
      $ossec_auth_force_key_mismatch                   = 'yes'
      $ossec_auth_force_disc_time                      = '1h'
      $ossec_auth_force_after_reg_time                 = '1h'
      $ossec_auth_purgue                               = 'yes'
      $ossec_auth_use_password                         = 'no'
      $ossec_auth_limit_maxagents                      = 'yes'
      $ossec_auth_ciphers                              = 'HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH'
      $ossec_auth_ssl_verify_host                      = 'no'
      $ossec_auth_ssl_manager_cert                     = '/var/ossec/etc/sslmanager.cert'
      $ossec_auth_ssl_manager_key                      = '/var/ossec/etc/sslmanager.key'
      $ossec_auth_ssl_auto_negotiate                   = 'no'


      # syscheck

      $ossec_syscheck_disabled                         = 'no'
      $ossec_syscheck_frequency                        = '43200'
      $ossec_syscheck_scan_on_start                    = 'yes'
      $ossec_syscheck_auto_ignore                      = 'no'
      $ossec_syscheck_directories_1                    = '/etc,/usr/bin,/usr/sbin'
      $ossec_syscheck_directories_2                    = '/bin,/sbin,/boot'
      $ossec_syscheck_whodata_directories_1            = 'no'
      $ossec_syscheck_realtime_directories_1           = 'no'
      $ossec_syscheck_whodata_directories_2            = 'no'
      $ossec_syscheck_realtime_directories_2           = 'no'
      $ossec_syscheck_ignore_list                      = ['/etc/mtab',
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
      $ossec_syscheck_ignore_type_1                    = '^/proc'
      $ossec_syscheck_ignore_type_2                    = '.log$|.swp$'

      $ossec_syscheck_max_eps = '100'
      $ossec_syscheck_process_priority = '10'
      $ossec_syscheck_synchronization_enabled = 'yes'
      $ossec_syscheck_synchronization_interval = '5m'
      $ossec_syscheck_synchronization_max_eps = '10'
      $ossec_syscheck_synchronization_max_interval = '1h'

      $ossec_syscheck_nodiff                           = '/etc/ssl/private.key'
      $ossec_syscheck_skip_nfs                         = 'yes'

      $ossec_ruleset_decoder_dir = 'ruleset/decoders'
      $ossec_ruleset_rule_dir = 'ruleset/rules'
      $ossec_ruleset_rule_exclude = '0215-policy_rules.xml'
      $ossec_ruleset_list = [ 'etc/lists/audit-keys',
        'etc/lists/amazon/aws-eventnames',
        'etc/lists/security-eventchannel',
      ]

      $ossec_ruleset_user_defined_decoder_dir = 'etc/decoders'
      $ossec_ruleset_user_defined_rule_dir = 'etc/rules'

      # Cluster

      $ossec_cluster_name                              = 'wazuh'
      $ossec_cluster_node_name                         = 'node01'
      $ossec_cluster_node_type                         = 'master'
      $ossec_cluster_key                               = 'KEY'
      $ossec_cluster_port                              = '1516'
      $ossec_cluster_bind_addr                         = '0.0.0.0'
      $ossec_cluster_nodes                             = ['NODE_IP']
      $ossec_cluster_hidden                            = 'no'
      $ossec_cluster_disabled                          = 'yes'

      $ossec_cluster_enable_firewall                   = 'no'


      #----- End of ossec.conf parameters -------

      $ossec_prefilter                     = false
      $ossec_integratord_enabled           = false


      $manage_client_keys                  = 'yes'
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
      $shared_agent_config_file = '/var/ossec/etc/shared/default/agent.conf'

      $config_mode = '0640'
      $config_owner = 'root'
      $config_group = 'wazuh'

      $keys_file = '/var/ossec/etc/client.keys'
      $keys_mode = '0640'
      $keys_owner = 'root'
      $keys_group = 'wazuh'


      $authd_pass_file = '/var/ossec/etc/authd.pass'

      $validate_cmd_conf = '/var/ossec/bin/verify-agent-conf -f %'

      $processlist_file = '/var/ossec/bin/.process_list'
      $processlist_mode = '0640'
      $processlist_owner = 'root'
      $processlist_group = 'wazuh'

      #API

      $wazuh_api_host = '0.0.0.0'
      $wazuh_api_port = '55000'

      $wazuh_api_file =  undef

      # Advanced configuration
      $wazuh_api_https_enabled = 'yes'
      $wazuh_api_https_key = 'server.key'
      $wazuh_api_https_cert = 'server.crt'
      $wazuh_api_https_use_ca = 'False'
      $wazuh_api_https_ca = 'ca.crt'
      $wazuh_api_ssl_protocol = 'TLSv1.2'
      $wazuh_api_ssl_ciphers  = '""'

      # Logging configuration
      # Values for API log level: disabled, info, warning, error, debug, debug2 (each level includes the previous level).
      $wazuh_api_logs_level = 'info'
      # Values for API log format: 'plain', 'json', 'plain,json', 'json,plain'
      $wazuh_api_logs_format = 'plain'

      # Cross-origin resource sharing: https://github.com/aio-libs/aiohttp-cors#usage
      $wazuh_api_cors_enabled = 'no'
      $wazuh_api_cors_source_route = '"*"'
      $wazuh_api_cors_expose_headers = '"*"'
      $wazuh_api_cors_allow_headers = '"*"'
      $wazuh_api_cors_allow_credentials = 'no'

      # Cache (time in seconds)
      $wazuh_api_cache_enabled = 'yes'
      $wazuh_api_cache_time = '0.750'

      # Access parameters
      $wazuh_api_access_max_login_attempts = 5
      $wazuh_api_access_block_time = 300
      $wazuh_api_access_max_request_per_minute = 300

      # Drop privileges (Run as ossec user)
      $wazuh_api_drop_privileges = 'yes'

      # Enable features under development
      $wazuh_api_experimental_features = 'no'

      # Enable remote commands
      $remote_commands_localfile = 'yes'
      $remote_commands_localfile_exceptions = []
      $remote_commands_wodle = 'yes'
      $remote_commands_wodle_exceptions = []
      $limits_eps = 'yes'

      # Wazuh API template path
      $wazuh_api_template = 'wazuh/wazuh_api_yml.erb'


      case $::osfamily {
        'Debian': {

          $agent_service  = 'wazuh-agent'
          $agent_package  = 'wazuh-agent'
          $service_has_status  = false
          $ossec_service_provider = undef
          $api_service_provider = undef
          $default_local_files = [
            { 'location' => '/var/log/syslog' , 'log_format' => 'syslog' },
            { 'location' => '/var/log/dpkg.log', 'log_format' => 'syslog' },
            { 'location' => '/var/log/kern.log', 'log_format' => 'syslog' },
            { 'location' => '/var/log/auth.log', 'log_format' => 'syslog' },
            {  'location' => '/var/ossec/logs/active-responses.log', 'log_format' => 'syslog'},
          ]
          case $::lsbdistcodename {
            'xenial': {
              $server_service = 'wazuh-manager'
              $server_package = 'wazuh-manager'
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
            /^(wheezy|stretch|buster|bullseye|sid|precise|trusty|vivid|wily|xenial|bionic|focal|groovy|jammy)$/: {
              $server_service = 'wazuh-manager'
              $server_package = 'wazuh-manager'
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
              $ossec_service_provider = 'systemd'
              $api_service_provider = 'systemd'
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
            'AlmaLinux': {
              if ( $::operatingsystemrelease =~ /^8.*/ ) {
                $ossec_service_provider = 'redhat'
                $api_service_provider = 'redhat'
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

      $agent_service  = 'WazuhSvc'
      $agent_package  = 'Wazuh Agent 4.4.4'
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
