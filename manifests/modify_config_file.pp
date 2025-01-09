# Class to modify configuration files (YAML or XML)
#
# @param file_path The path to the configuration file to be modified
# @param key_value_pairs An array of key-value pairs to be updated in the configuration file
class wazuh::modify_config_file (
  String $file_path,
  Array $key_value_pairs,
) {
  validate_absolute_path($file_path)

  # Load the stdlib module for escaping special characters
  include stdlib

  $key_value_pairs.each |$pair| {
    if ($pair =~ /^([^:]+):\s*(.+)$/) {
      $key = $1
      $value = $2

      $escaped_key = escape_regex($key)

      $escaped_key = escape($key)

      if ($file_content =~ /^${escaped_key}:\s*(.+)?$/) {
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
