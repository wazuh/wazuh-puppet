# Class to modify configuration files (YAML or XML)
#
# @param file_path The path to the configuration file to be modified
# @param key_value_pairs An array of key-value pairs to be updated in the configuration file
class wazuh::modify_config_file (
  String $file_path,
  Array $key_value_pairs,
) {

  # Load the stdlib module for escaping special characters
  include stdlib

  # Check if the file exists
  if file_exists($file_path) {
    $file_content = file($file_path)
  } else {
    $file_content = ''
  }

  $key_value_pairs.each |$pair| {
    if ($pair =~ /^([^:]+):\s*(.+)$/) {
      $key = $1
      $value = $2

      # Escape regex special characters
      $escaped_key = $key.gsub(/([.*+?^${}()|\[\]\\])/, '\\\\\1')

      if $file_content =~ /^${escaped_key}:\s*(.+)?$/ {
        $new_content = regsubst($file_content, /^${escaped_key}:\s*(.+)?$/, "${key}: ${value}")
        file { $file_path:
          ensure  => file,
          content => $new_content,
        }
      } else {
        file { $file_path:
          ensure  => file,
          content => "${file_content}\n${key}: ${value}\n",
        }
      }
    } else {
      fail("The line format '${pair}' is incorrect. It should be 'key: value'")
    }
  }
}
