# Defined type to install Wazuh components from custom URLs
# @param package_name Name of the Wazuh component (e.g., 'wazuh-manager')
# @param wazuh_version Version of the component to install (e.g., '4.9.2')
define wazuh::install_package (
  $package_name   = undef,
  $wazuh_version  = '5.0.0'
) {
  case $facts['kernel'] {
    'Linux': {
      $download_path = '/tmp'
      $package_list_path = '/tmp/packages_url.txt'
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
      $download_path = 'C:\\Temp'
      $package_msi_key = 'wazuh_agent_url_i386_msi'
      $package_list_path = 'C:/Windows/Temp/packages_url.txt'
      $msi_download_location = 'C:/Windows/Temp/wazuh-agent-installer.msi'
      Array[String] $install_options = ['/qn']
      Boolean $cleanup_msi = true
      file { $download_path:
        ensure => directory,
      }

      $download_dir = split($msi_download_location, /\\/)[0..-2].join('\\')
      file { $download_dir:
        ensure => directory,
      }

      exec { 'download_wazuh_msi':
        command  => "powershell.exe -Command \"
          \$packageListPath = \\\"${package_list_path}\\\";
          \$packageMsiKey = \\\"${package_msi_key}\\\";
          \$msiDownloadLocation = \\\"${msi_download_location}\\\";

          \$fileContent = Get-Content -Path \$packageListPath | Out-String;

          \$url = \$fileContent |
                Select-String -Pattern \\\"^\$packageMsiKey:\\\" |
                ForEach-Object { \$_.ToString().Split(':', 2)[1].Trim() };

          if (\$null -ne \$url -and \$url -ne '') {
            Write-Host \\\"URL found: \$url\\\";
            # Descargar el archivo
            try {
              Invoke-WebRequest -Uri \$url -OutFile \$msiDownloadLocation -UseBasicParsing;
              Write-Host \\\"Successfully downloaded \$url to \$msiDownloadLocation\\\";
            } catch {
              Write-Error \\\"Error downloading file from \$url: \$\_.Exception.Message\\\";
              exit 1; # Salir con código de error para que Puppet falle
            }
          } else {
            Write-Error \\\"Keyword '\$packageMsiKey' not found in \$packageListPath or URL is empty\\\";
            exit 1; # Salir con código de error si no se encuentra la clave
          }
        \"",
        provider => powershell,
        logoutput => true,
        subscribe => File[$download_dir],
        refreshonly => true,
      }

      package { "install_${package_name}":
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
