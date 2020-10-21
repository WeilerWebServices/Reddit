# Define: fluentd::match
# ===========================
#
# Configures a 'match' config file.
#
# Parameters
# ----------
# [*ensure*]
#   Default: 'present'
# [*priority*]
#   Defines the priority
#   Default: '30'
# [*pattern*]
#   Defines matching the pattern
#   Default: '**'
# [*config*]
#   Configuration, which must be a hash
#   Default: {}'
#
# Examples
# --------
#
# @example
#    ::fluentd::match { 'test':
#       priority => 30,
#       pattern  => '*.test'
#       config   => {
#         'flush_interval' => '30s',
#         'type'           => 'secure_forward',
#         'secure'         => 'yes',
#         'shared_key'     => 'my_shared_key',
#         'self_hostname'  => 'instance.test.com',
#         'ca_cert_path'   => '/path/to/ca.cert',
#         'server'         => [{
#           'host' => 'test.server.com'
#         }]
#       }
#     }
#
# Copyright
# ---------
#
# Copyright 2015 wywy, unless otherwise noted.
#
define fluentd::match (
  Enum['present', 'absent'] $ensure   = present,
  Integer                   $priority = 30,
  String                    $pattern  = '**',
  Hash                      $config   = {},
) {

  fluentd::config::file { "match-${title}":
    ensure   => $ensure,
    priority => $priority,
    content  => template( 'fluentd/match.erb'),
  }

}
