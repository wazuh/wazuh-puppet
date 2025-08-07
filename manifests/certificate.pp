# @summary Wraps openssl::certificate::x509 to additionally convert to pkcs8 key (necessary for OpenSearch admin)
#
# @param export_pkcs8
#   Whether to export the private key in PKCS8 format, necessary for OpenSearch admin
# @param pkcs8_extension
#   The file extension for the PKCS8 key
# @param algo
#   The encryption algorithm to use for the PKCS8 key, for use in Java
#
define wazuh::certificate (
  # All necessary params for openssl::certificate::x509
  Enum['present', 'absent']      $ensure = present,
  Optional[String]               $country = undef,
  Optional[String]               $organization = undef,
  Optional[String]               $unit = undef,
  Optional[String]               $state = undef,
  Optional[String]               $commonname = undef,
  Optional[String]               $locality = undef,
  Array                          $altnames = [],
  Array                          $keyusage = [],
  Array                          $extkeyusage = [],
  Optional[String]               $email = undef,
  Integer                        $days = 365,
  Stdlib::Absolutepath           $base_dir = '/etc/ssl/certs',
  Stdlib::Absolutepath           $cnf_dir = $base_dir,
  Stdlib::Absolutepath           $crt_dir = $base_dir,
  Stdlib::Absolutepath           $csr_dir = $base_dir,
  Stdlib::Absolutepath           $key_dir = $base_dir,
  Stdlib::Absolutepath           $cnf = "${cnf_dir}/${name}.cnf",
  Stdlib::Absolutepath           $crt = "${crt_dir}/${name}.crt",
  Stdlib::Absolutepath           $csr = "${csr_dir}/${name}.csr",
  Stdlib::Absolutepath           $key = "${key_dir}/${name}.key",
  Integer                        $key_size = 3072,
  Variant[String, Integer]       $owner = 'root',
  Variant[String, Integer]       $group = 'root',
  Variant[String, Integer]       $key_owner = $owner,
  Variant[String, Integer]       $key_group = $group,
  Stdlib::Filemode               $key_mode = '0600',
  Optional[String]               $password = undef,
  Boolean                        $force = true,
  Boolean                        $encrypted = true,
  Optional[Stdlib::Absolutepath] $ca = undef,
  Optional[Stdlib::Absolutepath] $cakey = undef,
  Optional[Variant[Sensitive[String[1]], String[1]]] $cakey_password = undef,
  # Params specific to this module
  Boolean $export_pkcs8     = false,
  String  $pkcs8_extension  = 'pk8',
  String  $algo             = 'PBE-SHA1-3DES',

) {
  openssl::certificate::x509 { $name:
    ensure         => $ensure,
    country        => $country,
    organization   => $organization,
    unit           => $unit,
    state          => $state,
    commonname     => $commonname,
    locality       => $locality,
    altnames       => $altnames,
    keyusage       => $keyusage,
    extkeyusage    => $extkeyusage,
    email          => $email,
    days           => $days,
    base_dir       => $base_dir,
    cnf_dir        => $cnf_dir,
    crt_dir        => $crt_dir,
    csr_dir        => $csr_dir,
    key_dir        => $key_dir,
    cnf            => $cnf,
    crt            => $crt,
    csr            => $csr,
    key            => $key,
    key_size       => $key_size,
    owner          => $owner,
    group          => $group,
    key_owner      => $key_owner,
    key_group      => $key_group,
    key_mode       => $key_mode,
    password       => $password,
    force          => $force,
    encrypted      => $encrypted,
    ca             => $ca,
    cakey          => $cakey,
    cakey_password => $cakey_password,
  }
  if $export_pkcs8 {
    $_cmd = [
      'openssl', 'pkcs8', '-topk8',
      '-inform', 'PEM',
      '-outform', 'PEM',
      '-in', $key,
      '-out', "${key}.${pkcs8_extension}",
      '-v1', $algo,
      '-nocrypt',
    ]
    exec { "export ${name} key to pkcs8":
      command     => $_cmd,
      path        => $facts['path'],
      subscribe   => OpenSSL::Certificate::X509[$name],
      refreshonly => true,
    }
  }
}
