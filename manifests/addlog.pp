#Define a log-file to add to ossec
define wazuh::addlog(
  $logfile,
  $logtype   = 'syslog',
  $frequency = undef,
) {
  require wazuh::params

  concat::fragment { "ossec.conf_localfile-${logfile}":
    target  => 'ossec.conf',
    content => template('wazuh/fragments/_localfile.erb'),
    order   => 20,
  }

}
