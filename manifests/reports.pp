# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
#Define for a Reports section
define wazuh::reports(
  String $report_title,
  String $report_email_to,
  String $report_group        = undef,
  String $report_category     = undef,
  Integer $report_rule        = undef,
  Integer[1,16] $report_level = undef,
  String $report_location     = undef,
  Variant[Stdlib::Host, Stdlib::IP::Address, Undef] $report_srcip = undef,
  String $report_user         = undef,
  Integer $report_order       = 70,
  Optional[Enum['yes', 'no']] $report_showlogs = undef,
) {
  # Validate required email parameter
  validate_email_address($report_email_to)

  # Build report fragment
  concat::fragment { "ossec.conf_reports-${title}":
    target  => 'ossec.conf',
    order   => $report_order,
    content => template('wazuh/fragments/_reports.erb')
  }
}
