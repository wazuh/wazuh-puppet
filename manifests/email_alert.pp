# Define an email alert
define wazuh::email_alert(
  $alert_email,
  $alert_group = false
) {
  require wazuh::params

  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 65,
    content => template('wazuh/email_alert.erb'),
  }
}
