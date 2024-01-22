# Change Log

See https://github.com/slimphp/Slim-Csrf/releases for a full list

## Next

- Added: Support for PHP 8.2 and 8.3

## 1.4.0

- Added: Allow to set token name and value in header

## 1.3.0

- Added: Support for PSR-12
- Added: Add XOR to token to avoid BREACH attack
- Change: PHP 7.3 is no longer supported

## 1.2.1

- Added: Implement iterator support for getLastKeyPair

## 1.2.0

- Added: Support PHP 8
- Changed: Remove support for PHP 7.1 and 7.2

## 1.1.0

- Changed: `remoteTokenFromStorage()` is now public
- Changed: Don't allow token in the body of a GET request
- Fixed: Prevent replay attack by removing token on valdiation

## 1.0.0

- Added: PSR-15 support

## 0.8.3

 - Fixed: Widen random_compat constraint in composer.json

## 0.8.2

- Fixed: Attach token name and value to request when persist mode is on

## 0.8.1

- Fixed: Default stroageis now $_SESSION again

## 0.8.0

- Added: Now supports "persistence mode", to persist a single CSRF name/value pair throughout the life of a user's session.  Added the following methods:

  - `protected getLastKeyPair` - gets the most recently generated key/value pair from storage.
  - `protected loadLastKeyPair` - gets the most recently generated key/value pair from storage, and assign it to `$this->keyPair`.
  - `public setPersistentTokenMode`
  - `public getPersistentTokenMode`

  Note that if CSRF token validation fails, then the token should be renewed regardless of the persistence setting.
    
  The methods `getTokenName` and `getTokenValue` now return `null` if `$this->keyPair` has not yet been set.

