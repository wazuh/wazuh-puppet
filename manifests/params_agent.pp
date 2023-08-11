# Copyright (C) 2015, Wazuh Inc.
# Wazuh-Agent configuration parameters
class wazuh::params_agent {
  $agent_package_version = '4.8.0'
  $agent_package_revision = '1'
  $agent_service_ensure = 'running'
  $agent_msi_download_location = 'https://packages.wazuh.com/4.x/windows'

  $agent_name = undef
  $agent_group = undef
  $agent_address = undef

  # Enable/Disable agent registration
  $manage_client_keys = 'yes'

  # Configure the format of internal logs
  $logging_log_format = 'plain'

  # Agents registration parameters
  $wazuh_agent_cert = undef
  $wazuh_agent_key = undef
  $wazuh_agent_cert_path = undef
  $wazuh_agent_key_path = undef
  $agent_auth_password = undef
  $wazuh_manager_root_ca_pem = undef
  $wazuh_manager_root_ca_pem_path = undef
  $authd_pass_file = '/var/ossec/etc/authd.pass'

  # ossec.conf generation variables
  $configure_rootcheck = true
  $configure_wodle_openscap = true
  $configure_wodle_cis_cat = true
  $configure_wodle_osquery = true
  $configure_wodle_syscollector = true
  $configure_wodle_docker_listener = false
  $configure_sca = true
  $configure_syscheck = true
  $configure_localfile = true
  $configure_active_response = true

  # ossec.conf templates paths
  $ossec_conf_template = 'wazuh/wazuh_agent.conf.erb'
  $ossec_rootcheck_template = 'wazuh/fragments/_rootcheck.erb'
  $ossec_wodle_openscap_template = 'wazuh/fragments/_wodle_openscap.erb'
  $ossec_wodle_cis_cat_template = 'wazuh/fragments/_wodle_cis_cat.erb'
  $ossec_wodle_osquery_template = 'wazuh/fragments/_wodle_osquery.erb'
  $ossec_wodle_syscollector_template = 'wazuh/fragments/_wodle_syscollector.erb'
  $ossec_wodle_docker_listener_template = 'wazuh/fragments/_wodle_docker_listener.erb'
  $ossec_sca_template = 'wazuh/fragments/_sca.erb'
  $ossec_syscheck_template = 'wazuh/fragments/_syscheck.erb'
  $ossec_localfile_template = 'wazuh/fragments/_localfile.erb'
  $ossec_auth = 'wazuh/fragments/_auth.erb'
  $ossec_cluster = 'wazuh/fragments/_cluster.erb'
  $ossec_active_response_template = 'wazuh/fragments/_activeresponse.erb'

  # ossec.conf blocks

  ## Server block configuration
  $wazuh_register_endpoint = undef
  $wazuh_reporting_endpoint = undef
  $ossec_port = '1514'
  $ossec_protocol = 'tcp'
  $wazuh_max_retries = '5'
  $wazuh_retry_interval = '5'
  $ossec_config_ubuntu_profiles = 'ubuntu, ubuntu18, ubuntu18.04'
  $ossec_config_centos_profiles = 'centos, centos7, centos7.6'
  $ossec_notify_time = 10
  $ossec_time_reconnect = 60
  $ossec_auto_restart = 'yes'
  $ossec_crypto_method = 'aes'

  ## Buffers
  $client_buffer_disabled = 'no'
  $client_buffer_queue_size = 5000
  $client_buffer_events_per_second = 500

  # active response
  $active_response_disabled                        = 'no'
  $active_response_ca_verification                 = 'yes'
  $active_response_repeated_offenders              = []

  # agent autoenrollment
  $wazuh_enrollment_enabled                        = undef
  $wazuh_enrollment_manager_address                = undef
  $wazuh_enrollment_port                           = undef
  $wazuh_enrollment_agent_name                     = undef
  $wazuh_enrollment_groups                         = undef
  $wazuh_enrollment_agent_address                  = undef
  $wazuh_enrollment_ssl_cipher                     = undef
  $wazuh_enrollment_server_ca_path                 = undef
  $wazuh_enrollment_agent_cert_path                = undef
  $wazuh_enrollment_agent_key_path                 = undef
  $wazuh_enrollment_auth_pass                      = undef
  $wazuh_enrollment_auth_pass_path                 = $authd_pass_file
  $wazuh_enrollment_auto_method                    = undef
  $wazuh_delay_after_enrollment                    = undef
  $wazuh_enrollment_use_source_ip                  = undef

  # Other required to define variables
  $manage_repo = true
  $manage_firewall = false
  $selinux = false
  $configure_labels = false
  $ossec_labels_template = 'wazuh/fragments/_labels.erb'
  $ossec_labels = []


  ## Rootcheck
  $ossec_rootcheck_disabled = 'no'
  $ossec_rootcheck_check_files = 'yes'
  $ossec_rootcheck_check_trojans = 'yes'
  $ossec_rootcheck_check_dev = 'yes'
  $ossec_rootcheck_check_sys = 'yes'
  $ossec_rootcheck_check_pids = 'yes'
  $ossec_rootcheck_check_ports = 'yes'
  $ossec_rootcheck_check_if = 'yes'
  $ossec_rootcheck_frequency = 36000
  $ossec_rootcheck_ignore_list = []
  $ossec_rootcheck_ignore_sregex_list = []
  $ossec_rootcheck_rootkit_files = '/var/ossec/etc/shared/rootkit_files.txt'
  $ossec_rootcheck_rootkit_trojans = '/var/ossec/etc/shared/rootkit_trojans.txt'
  $ossec_rootcheck_skip_nfs = 'yes'

  # Example: ["/var/ossec/etc/shared/system_audit_rcl.txt"]
  $ossec_rootcheck_system_audit = []

  # Rootcheck Windows
  $ossec_rootcheck_windows_disabled = 'no'
  $ossec_rootcheck_windows_windows_apps = './shared/win_applications_rcl.txt'
  $ossec_rootcheck_windows_windows_malware = './shared/win_malware_rcl.txt'


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

  ## Windows
  $sca_windows_enabled = 'yes'
  $sca_windows_scan_on_start = 'yes'
  $sca_windows_interval = '12h'
  $sca_windows_skip_nfs = 'yes'
  $sca_windows_policies = []

  ## <else>
  $sca_else_enabled = 'yes'
  $sca_else_scan_on_start = 'yes'
  $sca_else_interval = '12h'
  $sca_else_skip_nfs = 'yes'
  $sca_else_policies = []


  ## open-scap
  $wodle_openscap_disabled = 'yes'
  $wodle_openscap_timeout = '1800'
  $wodle_openscap_interval = '1d'
  $wodle_openscap_scan_on_start = 'yes'


  ## syscheck
  $ossec_syscheck_disabled = 'no'
  $ossec_syscheck_frequency = '43200'
  $ossec_syscheck_scan_on_start = 'yes'
  $ossec_syscheck_auto_ignore = undef
  $ossec_syscheck_directories_1 = '/etc,/usr/bin,/usr/sbin'
  $ossec_syscheck_directories_2 = '/bin,/sbin,/boot'
  $ossec_syscheck_report_changes_directories_1 = 'no'
  $ossec_syscheck_whodata_directories_1 = 'no'
  $ossec_syscheck_realtime_directories_1 = 'no'
  $ossec_syscheck_report_changes_directories_2 = 'no'
  $ossec_syscheck_whodata_directories_2 = 'no'
  $ossec_syscheck_realtime_directories_2 = 'no'
  $ossec_syscheck_ignore_list = ['/etc/mtab',
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
  $ossec_syscheck_ignore_type_1 = '^/proc'
  $ossec_syscheck_ignore_type_2 = '.log$|.swp$'

  $ossec_syscheck_max_eps = '100'
  $ossec_syscheck_process_priority = '10'
  $ossec_syscheck_synchronization_enabled = 'yes'
  $ossec_syscheck_synchronization_interval = '5m'
  $ossec_syscheck_synchronization_max_eps = '10'
  $ossec_syscheck_synchronization_max_interval = '1h'

  $ossec_syscheck_nodiff = '/etc/ssl/private.key'
  $ossec_syscheck_skip_nfs = 'yes'


  # Audit
  $audit_manage_rules                = false
  $audit_buffer_bytes                = '8192'
  $audit_backlog_wait_time           = '0'
  $audit_rules                       = [
    "-b ${audit_buffer_bytes}",
    "--backlog_wait_time ${audit_backlog_wait_time}",
    '-f 1'
  ]

  $windows_audit_interval = 300

  # active-response
  $active_response_linux_ca_store = '/var/ossec/etc/wpk_root.pem'


  # OS specific configurations
  case $::kernel {
    'Linux': {
      $agent_package_name = 'wazuh-agent'
      $agent_service_name = 'wazuh-agent'

      $download_path = '/tmp'

      # Wazuh config folders and modes
      $config_file = '/var/ossec/etc/ossec.conf'
      $shared_agent_config_file = '/var/ossec/etc/shared/agent.conf'

      $config_mode = '0640'
      $config_owner = 'root'
      $config_group = 'wazuh'

      $keys_file = '/var/ossec/etc/client.keys'
      $keys_mode = '0640'
      $keys_owner = 'root'
      $keys_group = 'wazuh'

      $validate_cmd_conf = '/var/ossec/bin/verify-agent-conf -f %'

      $processlist_file = '/var/ossec/bin/.process_list'
      $processlist_mode = '0640'
      $processlist_owner = 'root'
      $processlist_group = 'wazuh'

      # ossec.conf blocks

      # Wodles

      ## docker-listener
      $wodle_docker_listener_disabled = 'yes'

      ## cis-cat
      $wodle_ciscat_disabled = 'yes'
      $wodle_ciscat_timeout = '1800'
      $wodle_ciscat_interval = '1d'
      $wodle_ciscat_scan_on_start = 'yes'
      $wodle_ciscat_java_path = 'wodles/java'
      $wodle_ciscat_ciscat_path = 'wodles/ciscat'

      ## osquery
      $wodle_osquery_disabled = 'yes'
      $wodle_osquery_run_daemon = 'yes'
      $wodle_osquery_log_path = '/var/log/osquery/osqueryd.results.log'
      $wodle_osquery_config_path = '/etc/osquery/osquery.conf'
      $wodle_osquery_add_labels = 'yes'
      $wodle_osquery_bin_path = '/usr/bin/osqueryd'

      ## syscollector
      $wodle_syscollector_disabled = 'no'
      $wodle_syscollector_interval = '1h'
      $wodle_syscollector_scan_on_start = 'yes'
      $wodle_syscollector_hardware = 'yes'
      $wodle_syscollector_os = 'yes'
      $wodle_syscollector_network = 'yes'
      $wodle_syscollector_packages = 'yes'
      $wodle_syscollector_ports = 'yes'
      $wodle_syscollector_processes = 'yes'
      $wodle_syscollector_hotfixes = undef

      $ossec_ruleset_decoder_dir = 'ruleset/decoders'
      $ossec_ruleset_rule_dir = 'ruleset/rules'
      $ossec_ruleset_rule_exclude = '0215-policy_rules.xml'
      $ossec_ruleset_list = [ 'etc/lists/audit-keys',
        'etc/lists/amazon/aws-eventnames',
        'etc/lists/security-eventchannel',
      ]

      $ossec_ruleset_user_defined_decoder_dir = 'etc/decoders'
      $ossec_ruleset_user_defined_rule_dir = 'etc/rules'

      case $::osfamily {
        'Debian': {
          $service_has_status = false
          $ossec_service_provider = undef

          $default_local_files = [
            { 'location' => '/var/log/syslog', 'log_format' => 'syslog' },
            { 'location' => '/var/log/kern.log', 'log_format' => 'syslog' },
            { 'location' => '/var/log/auth.log', 'log_format' => 'syslog' },
            { 'location' => '/var/log/dpkg.log', 'log_format' => 'syslog' },
            { 'location' => '/var/ossec/logs/active-responses.log', 'log_format' => 'syslog' },
          ]
          case $::lsbdistcodename {
            'xenial': {
              $wodle_openscap_content = {
                'ssg-ubuntu-1604-ds.xml'        => {
                  'type'   => 'xccdf',
                  profiles => ['xccdf_org.ssgproject.content_profile_common'],
                }, 'cve-ubuntu-xenial-oval.xml' => {
                  'type' => 'oval'
                }
              }
            }
            'jessie': {
              $wodle_openscap_content = {
                'ssg-debian-8-ds.xml'   => {
                  'type'   => 'xccdf',
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
          $service_has_status = true

          $default_local_files = [
            { 'location' => '/var/log/audit/audit.log', 'log_format' => 'audit' },
            { 'location' => '/var/ossec/logs/active-responses.log', 'log_format' => 'syslog' },
            { 'location' => '/var/log/messages', 'log_format' => 'syslog' },
            { 'location' => '/var/log/secure', 'log_format' => 'syslog' },
            { 'location' => '/var/log/maillog', 'log_format' => 'syslog' },
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

                $wodle_openscap_content = {
                  'ssg-centos-6-ds.xml' => {
                    'type'   => 'xccdf',
                    profiles => [
                      'xccdf_org.ssgproject.content_profile_pci-dss',
                      'xccdf_org.ssgproject.content_profile_server',
                    ]
                  }
                }
              }
              if ( $::operatingsystemrelease =~ /^7.*/ ) {
                $ossec_service_provider = 'systemd'

                $wodle_openscap_content = {
                  'ssg-centos-7-ds.xml' => {
                    'type'   => 'xccdf',
                    profiles => [
                      'xccdf_org.ssgproject.content_profile_pci-dss',
                      'xccdf_org.ssgproject.content_profile_common',
                    ]
                  }
                }
              }
            }
            /^(RedHat|OracleLinux)$/: {
              if ( $::operatingsystemrelease =~ /^6.*/ ) {
                $ossec_service_provider = 'redhat'

                $wodle_openscap_content = {
                  'ssg-rhel-6-ds.xml'   => {
                    'type'   => 'xccdf',
                    profiles => [
                      'xccdf_org.ssgproject.content_profile_pci-dss',
                      'xccdf_org.ssgproject.content_profile_server',
                    ]
                  },
                  'cve-redhat-6-ds.xml' => {
                    'type' => 'xccdf',
                  }
                }
              }
              if ( $::operatingsystemrelease =~ /^7.*/ ) {
                $ossec_service_provider = 'systemd'

                $wodle_openscap_content = {
                  'ssg-rhel-7-ds.xml'   => {
                    'type'   => 'xccdf',
                    profiles => [
                      'xccdf_org.ssgproject.content_profile_pci-dss',
                      'xccdf_org.ssgproject.content_profile_common',
                    ]
                  },
                  'cve-redhat-7-ds.xml' => {
                    'type' => 'xccdf',
                  }
                }
              }
              if ( $::operatingsystemrelease =~ /^8.*/ ) {
                $ossec_service_provider = 'systemd'

                $wodle_openscap_content = {
                  'ssg-rhel-8-ds.xml'   => {
                    'type'   => 'xccdf',
                    profiles => [
                      'xccdf_org.ssgproject.content_profile_pci-dss',
                      'xccdf_org.ssgproject.content_profile_common',
                    ]
                  },
                  'cve-redhat-8-ds.xml' => {
                    'type' => 'xccdf',
                  }
                }
              }
            }
            'Fedora': {
              if ( $::operatingsystemrelease =~ /^(23|24|25).*/ ) {
                $ossec_service_provider = 'redhat'

                $wodle_openscap_content = {
                  'ssg-fedora-ds.xml' => {
                    'type'   => 'xccdf',
                    profiles => [
                      'xccdf_org.ssgproject.content_profile_standard',
                      'xccdf_org.ssgproject.content_profile_common',
                    ]
                  },
                }
              }
            }
            'AlmaLinux': {
              if ( $::operatingsystemrelease =~ /^8.*/ ) {
                $ossec_service_provider = 'redhat'
              }
            }
            'Rocky': {
              if ( $::operatingsystemrelease =~ /^8.*/ ) {
                $ossec_service_provider = 'redhat'
              }
            }
            default: { fail('This ossec module has not been tested on your distribution') }
          }
        }
        'Suse': {
          $service_has_status = true

          $default_local_files = [
            { 'location' => '/var/log/audit/audit.log', 'log_format' => 'audit' },
            { 'location' => '/var/ossec/logs/active-responses.log', 'log_format' => 'syslog' },
            { 'location' => '/var/log/messages', 'log_format' => 'syslog' },
            { 'location' => '/var/log/secure', 'log_format' => 'syslog' },
            { 'location' => '/var/log/maillog', 'log_format' => 'syslog' },
          ]
          case $::operatingsystem {
            'SLES': {
              if ( $::operatingsystemrelease =~ /^(12|15).*/ ) {
                $ossec_service_provider = 'redhat'
              }
            }
            default: { fail('This ossec module has not been tested on your distribution') }
          }
        }
        default: { fail('This ossec module has not been tested on your distribution') }
      }
    }
    'windows': {
      $config_file = 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf'
      $shared_agent_config_file = 'C:\\Program Files (x86)\\ossec-agent\\shared\\agent.conf'
      $config_group = 'Administrators'
      $download_path = 'C:\\Temp'
      $config_mode = '0664'

      $keys_file = 'C:\\Program Files (x86)\\ossec-agent\\client.keys'

      $agent_package_name = 'Wazuh Agent'
      $agent_service_name = 'WazuhSvc'
      $service_has_status = true
      $ossec_service_provider = undef

      # Wodles

      ## syscollector
      $wodle_syscollector_disabled = 'no'
      $wodle_syscollector_interval = '1h'
      $wodle_syscollector_scan_on_start = 'yes'
      $wodle_syscollector_hardware = 'yes'
      $wodle_syscollector_os = 'yes'
      $wodle_syscollector_network = 'yes'
      $wodle_syscollector_packages = 'yes'
      $wodle_syscollector_ports = 'yes'
      $wodle_syscollector_processes = 'yes'
      $wodle_syscollector_hotfixes = 'yes'

      ## cis-cat
      $wodle_ciscat_disabled = 'yes'
      $wodle_ciscat_timeout = '1800'
      $wodle_ciscat_interval = '1d'
      $wodle_ciscat_scan_on_start = 'yes'
      $wodle_ciscat_java_path = '\\server\jre\bin\java.exe'
      $wodle_ciscat_ciscat_path = 'C:\cis-cat'

      ## osquery
      $wodle_osquery_disabled = 'yes'
      $wodle_osquery_run_daemon = 'yes'
      $wodle_osquery_bin_path = 'C:\Program Files\osquery\osqueryd'
      $wodle_osquery_log_path = 'C:\Program Files\osquery\log\osqueryd.results.log'
      $wodle_osquery_config_path = 'C:\Program Files\osquery\osquery.conf'
      $wodle_osquery_add_labels = 'yes'

      # active-response
      $active_response_windows_ca_store = 'wpk_root.pem'

      # TODO
      $validate_cmd_conf = undef

      # Pushed by shared agent config now
      $default_local_files = [
        {
          'location'   => 'Application',
          'log_format' => 'eventchannel'
        },
        {
          'location'   => 'Security',
          'log_format' => 'eventchannel',
          'query'      => 'Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658 \
and EventID != 4663 and EventID != 4660 and EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907 \
and EventID != 5152 and EventID != 5157]'
        },
        {
          'location'   => 'System',
          'log_format' => 'eventchannel'
        },
        {
          'location'   => 'active-response\active-responses.log',
          'log_format' => 'syslog'
        },
      ]
    }
    default: { fail('This ossec module has not been tested on your distribution') }
  }
}
