# Defines the allowed structure of an Azure logs configuration
type Wazuh::Wodle_azurelogs = Hash[
  String, Struct[
    {
      application_id  => String[1],
      application_key => String[1],
      tennant         => Stdlib::Fqdn,
      workspace       => String[1],
      interval        => String[1],
      run_on_start    => Enum['yes', 'no'],
      time_offset     => String[1],
    },
  ]
]
