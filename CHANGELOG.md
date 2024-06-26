# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [15.1.0] - 2021-04-30

### Added
- scopes to verify endpoint

## [15.0.0] - 2021-04-16

### Added
- username to verify endpoint and JWT

### Updated
- Updated README

## [14.1.2] - 2021-04-15

### Updated
- Updated README

## [14.1.1] - 2021-04-14

### Updated
- Updated README

## [14.1.0] - 2021-04-13

### Added
- Added expiry to verify endpoint

### Updated
- Updated README

## [14.0.1] - 2021-04-13

### Changed
- Small internal refactor

## [14.0.0] - 2021-04-12

### Added
- Added biscuit for scoping

### Updated
- Updated README

## [13.0.2] - 2021-04-10

### Updated
- Updated README

## [13.0.1] - 2021-04-10

### Updated
- Updated README

## [13.0.0] - 2021-04-08

### Added
- Two Factor Auth
- User password reset

### Updated
- Updated README

## [12.0.2] - 2021-04-08

### Updated
- Updated README

## [12.0.1] - 2021-04-08

### Updated
- Updated README

## [12.0.0] - 2021-04-08

### Added
- Added JWT custom scopes on user

### Updated
- Updated README

## [11.2.0] - 2021-04-06

### Added
- Added zxcvbn password strength checker

### Fixed
- Fixed JWT issued not being in JSON format

## [11.1.0] - 2021-04-06

### Added
- Added use your own SSL cert
- Added health check endpoints

### Updated
- Updated README

## [11.0.0] - 2021-04-05

### Added
- Added email field on user
- Added data field on user
- Added user email address validation
- Added update user endpoint

## [10.0.0] - 2021-04-05

### Fixed
- Fixed infinite SSE event sending

### Changed
- Changed RocksDB keys for user and event to be tenanted
- Changed default RocksDB path from tmp to db
- Changed create user endpoint URL

### Added
- Added list users endpoint
- Added revoke user endpoint
- Added get user endpoint
- Added unrevoke user endpoint

### Updated
- Updated README

## [9.1.0] - 2021-04-02

### Added
- Added verify endpoint 

## [9.0.2] - 2021-03-25

### Fixed
- Fixed keys on event

## [9.0.0] - 2021-03-25

### Removed
- Removed tenant_name from event - uses users event name

## [8.1.x] - 2021-03-25

### Added
- Added http basic auth

## [8.0.x] - 2021-03-23

### Added
- Adds admin_token to create user and command args
- Adds multi-tenancy

## [7.0.x] - 2021-03-22

### Added
- Added tide-acme

## Changed
- Changed command args

## [6.1.x] - 2021-03-21

### Changed
- Replaced broker-ntp with nippy

## [6.0.x] - 2021-03-20

### Changed
- Replaced Warp with Tide
- Replaced Sled with RocksDB

### Removed
- Rmmoved GET JSON API endpoints
- Removed multi-tenancy
- Removed timestamps, event dispatcher, and cancellation
- Removed broker-grid support (current version)
