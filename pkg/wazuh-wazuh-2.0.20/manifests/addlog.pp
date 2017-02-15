#Define a log-file to add to ossec
define ossec::addlog(
  $logfile,
  $agent_log = false,
  $logtype = 'syslog',
) {
  require ossec::params
# Issue #30
  if $agent_log
  {
    $ossec_notify = Service[$ossec::params::agent_service]
  } else {
    $ossec_notify = Service[$ossec::params::server_service]
  }


  concat::fragment { "ossec.conf_20-${logfile}":
    target  => $ossec::params::config_file,
    content => template('ossec/20_ossecLogfile.conf.erb'),
    order   => 20,
    notify  => $ossec_notify
  }

}
