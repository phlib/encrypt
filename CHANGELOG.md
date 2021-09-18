# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]
### Changed
- Use SemVer for dependency versions. This effectively removes unintended
  support for PHP v8, as this package has only been tested for PHP v5.4 - v7.1.
- Use fully-qualified paths for global functions. Minor efficiency improvement
  and prevents overwriting functions critical to the encryption. 
### Removed
- **BC break**: Removed support for PHP versions < v7.1 as they are no longer
  [actively supported](https://php.net/supported-versions.php) by the PHP project.

## [2.0.0] - 2016-04-06
- Use separate keys for encryption and authentication.

## [1.0.3] - 2016-04-06
- Fix shim implementation of `hash_pbkdf2` to work properly when `length` is zero.

## [1.0.2] - 2016-03-23
- Use `random_bytes()` instead of `openssl_random_pseudo_bytes()`. This should
  generate far more cryptographically secure random bytes, and should also be more
  [fork safe](https://wiki.openssl.org/index.php/Random_Numbers#Fork_Safety).

## [1.0.1] - 2016-02-12
- Add support for PHP v5.4. Now that we've got a polyfill for hash_pbkdf2,
  we should be able to safely support PHP v5.4.

## [1.0.0] - 2016-02-12
- Initial release
