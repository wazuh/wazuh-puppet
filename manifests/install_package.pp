# Defined type to install Wazuh components from custom URLs
# @param package_name Name of the Wazuh component (e.g., 'wazuh-manager')
# @param wazuh_version Version of the component to install (e.g., '4.9.2')
define wazuh::install_package (
  $package_name   = $wazuh::param_install_package::package_name,
  $wazuh_version  = $wazuh::param_install_package::package_version,
  $download_path  = $wazuh::param_install_package::download_path,
  $package_msi_key = $wazuh::param_install_package::package_msi_key
  $package_list_path = $wazuh::param_install_package::package_list_path,
  $msi_download_location = $wazuh::param_install_package::msi_download_location,
  $install_options = $wazuh::param_install_package::install_options,
  $cleanup_msi = $wazuh::param_install_package::cleanup_msi,
) inherits wazuh::param_install_package {
  case $facts['kernel'] {
    'Linux': {
      # Determine package provider based on OS family
      $provider = $facts['os']['family'] ? {
        'Debian' => 'dpkg',  # Correct provider name for .deb packages
        'RedHat' => 'rpm',   # Keep rpm for RedHat
        default  => fail("Unsupported OS family: ${facts['os']['family']}"),
      }

      # Determine package format (deb/rpm) based on OS family
      $compatibility = $facts['os']['family'] ? {
        'Debian' => 'deb',
        'RedHat' => 'rpm',
        default  => fail("Unsupported OS family: ${facts['os']['family']}"),
      }

      # Normalize architecture naming conventions
      $architecture = $facts['os']['architecture']

      # Generate package identifier package
      $package = "${package_name}_url_${architecture}_${compatibility}"

      # Download specific package using extracted URL
      exec { "download_${package}":
        command => "sh -c 'url=\$(grep -F '${package}:' /tmp/artifacts_url.txt | tr -d \"\\r\" | cut -d \" \" -f2); curl -o ${download_path}/${package} \"\$url\"'",
        unless  => "test -f ${download_path}/${package} && dpkg -I ${download_path}/${package} >/dev/null 2>&1",
        path    => ['/usr/bin', '/bin', '/sbin', '/usr/sbin'],
        timeout => 600,
      }

      # Install the package using correct provider
      package { "install_${package_name}":
        ensure   => installed,
        provider => $provider,  # Now using validated provider names
        source   => "/tmp/${package}",
        require  => Exec["download_${package}"],
      }
    }
    'windows': {
      file { $download_path:
        ensure => directory,
      }

      $deferred_content = Deferred('file', [$package_list_path])

      $package_msi_url = inline_epp(@(END_EPP), {
          content     => $deferred_content,
          key_to_find => $agent_msi_key,
          filepath    => $package_list_path,
      })
      <%- | Deferred $content, String $key_to_find, String $filepath | -%>
      <% $lines = $content.split("\n") %>
      <% $matching_lines = $lines.filter |$line| { $line =~ /^${key_to_find}:/ } %>
      <% if $matching_lines.length == 1 { %>
      <%   $match_result = $matching_lines[0].match(/^${key_to_find}:\s*(.*)\s*$/) %>
      <%   if $match_result and $match_result.length > 0 { $match_result[0] } %>
      <%   else { fail("Error parsing line for key '${key_to_find}' in file '${filepath}'. Line: ${matching_lines[0]}") } %>
      <% } elsif $matching_lines.length > 1 { %>
      <%   fail("Found multiple lines for key '${key_to_find}' in file '${filepath}'") %>
      <% } else { %>
      <%   fail("Key '${key_to_find}' not found in file '${filepath}'") %>
      <% } -%>
      END_EPP

      archive { 'download_msi_package':
        ensure  => present,
        path    => $msi_download_location,
        source  => $package_msi_url,
        extract => false,
        cleanup => false,
        before  => Package[$package_name],
      }

      package { $package_name:
        ensure          => installed,
        provider        => 'msi',
        source          => $msi_download_location,
        install_options => $install_options,
        require         => Archive['download_msi_package'],
      }

      if $cleanup_msi {
        file { 'remove_downloaded_msi':
          path    => $msi_download_location,
          ensure  => absent,
          require => Package[$package_name],
        }
      }
    }
    default: {
      fail("OS ${facts['os']['name']} is not supported")
    }
  }
}
