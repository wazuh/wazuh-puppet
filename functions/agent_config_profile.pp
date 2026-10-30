# Copyright (C) 2015, Wazuh Inc.

# Builds the <config-profile> value the same way the Wazuh agent package does.
# The package takes the OS name and version from /etc/os-release
# (src/init/dist-detect.sh, RPM) or from lsb_release (DEB postinst), gen_ossec.sh
# splits them, and inst-functions.sh formats the value: the name, then the major
# version and, unless it is absent or "0", the major.minor version.
# Returns undef on Windows.
function wazuh::agent_config_profile(
  Optional[String] $os_name,
  Optional[String] $os_full  = undef,
  Optional[String] $os_major = undef,
) >> Optional[String] {
  if $os_name == undef {
    return undef
  }
  $lower_name = downcase($os_name)
  if $lower_name == 'windows' {
    return undef
  }

  $profile_name = $os_name ? {
    'RedHat'      => 'rhel',
    'OracleLinux' => 'ol',
    'Amazon'      => 'amzn',
    'openSUSE'    => 'opensuse-leap',
    default       => $lower_name,
  }

  # Debian: the package uses lsb_release -sr, which returns the major version only
  $version = ($lower_name == 'debian' and $os_major =~ String[1]) ? {
    true    => $os_major,
    default => $os_full,
  }

  $parts = $version ? {
    String  => $version.match(/^[^0-9]*(\d+)(?:\.(\d+))?/),
    default => undef,
  }

  if $parts == undef {
    $profile_name
  } elsif $parts[2] == undef or $parts[2] == '0' {
    "${profile_name}, ${profile_name}${parts[1]}"
  } else {
    "${profile_name}, ${profile_name}${parts[1]}, ${profile_name}${parts[1]}.${parts[2]}"
  }
}
