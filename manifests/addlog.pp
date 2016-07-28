#Define a log-file to add to ossec
define wazuh::addlog(
  $logfile,
  $agent_log = false,
  $logtype = 'syslog',
) {
  require wazuh::params

  if $agent_log 
  {
    $ossec_notify = Service[$wazuh::params::agent_service]
  } else {
    $ossec_notify = Service[$wazuh::params::server_service]
  }


  concat::fragment { "ossec.conf_20-${logfile}":
    target  => $wazuh::params::config_file,
    content => template('wazuh/20_ossecLogfile.conf.erb'),
    order   => 20,
    notify  => $ossec_notify
  }

}
