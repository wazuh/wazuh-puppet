# Define an email alert
define ossec::email_alert(
  $alert_email,
  $alert_group = false
) {
  require ossec::params

  concat::fragment { $name:
    target  => $ossec::params::config_file,
    order   => 65,
    content => template('ossec/email_alert.erb'),
  }
}
