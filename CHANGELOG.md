# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

## [3.0.0] - 2021-08-18
### Added
- Add specific support for PHP v8.
- Type declarations have been added to all properties, method parameters and
  return types where possible.
### Changed
- Use SemVer for dependency versions.
- Use fully-qualified paths for global functions. Minor efficiency improvement
  and prevents overwriting functions critical to the encryption. 
- **BC break**: Reduce visibility of internal methods and properties. These
  members are not part of the public API. No impact to standard use of this
  package. If an implementation has a use case which needs to override these
  members, please submit a pull request explaining the change.
### Removed
- **BC break**: Removed support for PHP versions <= v7.3 as they are no longer
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
