# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
#Define for a Reports section
define wazuh::reports(
  Optional[String] $r_group               = undef,
  Optional[String] $r_category            = undef,
  Optional[Integer] $r_rule               = undef,
  Optional[Integer[1,16]] $r_level        = undef,
  Optional[String] $r_location            = undef,
  Optional[String] $r_srcip               = undef,
  Optional[String] $r_user                = undef,
  String $r_title                         = '',
  String $r_email_to                      = '',
  Optional[Enum['yes', 'no']] $r_showlogs = undef,
) {

  require wazuh::params

  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 70,
    content => template('wazuh/fragments/_reports.erb')
  }
}
