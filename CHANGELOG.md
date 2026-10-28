# Changelog

## [1.2.0](https://github.com/seatling/sdks/compare/v1.1.0...v1.2.0) (2026-10-28)


### Features

* add go sdk ([44d4467](https://github.com/seatling/sdks/commit/44d4467cd665dceeadf1b1eacb9633d68de64b53))
* add sdks ([b93623d](https://github.com/seatling/sdks/commit/b93623d6bfe489631e993e113464d37c6d3abc03))
* **api:** standardize on RFC 9457 problem details and harmonize openapi contract ([8281507](https://github.com/seatling/sdks/commit/8281507bbb60864a91df41526112314e8c0f8125))


### Bug Fixes

* **core:** adapt rust core to updated cargo dependencies ([0c428a3](https://github.com/seatling/sdks/commit/0c428a3c0dbb9d1cdda3d7c83bc19bd5ceb8e83b))
* **core:** allow unused mut on stored keystore in test_core for non-windows ([2c2cf3c](https://github.com/seatling/sdks/commit/2c2cf3ca2953699d46f2b8ec85c5c9a8f1dc9c65))
* **core:** ensure deterministic zero secret for HardwareSealed tier on non-windows ([344acee](https://github.com/seatling/sdks/commit/344acee2432bd00e2a7704c3797aac8dfc46e135))
* **core:** resolve cross-platform clippy lints in platform modules and keystore ([7c79eb6](https://github.com/seatling/sdks/commit/7c79eb608d0edd1afee3a4e32364fbc910a996b4))
* **core:** sync keystore timeline for verified offline lease and setup MSVC in CI ([195694a](https://github.com/seatling/sdks/commit/195694a854e58b129fd49becbabfef6fda729bf8))
* **core:** use statvfs for macos disk fsid to fix libc compilation ([212b111](https://github.com/seatling/sdks/commit/212b111cc5fc491bb24cd30e91e3f0f013501cf0))
* **go:** remove disallowed -Wl,--exclude-libs,ALL from linux cgo LDFLAGS ([d980b73](https://github.com/seatling/sdks/commit/d980b73b1f9e812492cea90d1536e8cb99d32e19))
* improve security and error handling ([641efb3](https://github.com/seatling/sdks/commit/641efb3da8db166c1c8821bab7ec32f70d87e94e))

## [1.1.0](https://github.com/seatling/sdks/compare/node-v1.0.0...node-v1.1.0) (2026-10-21)


### Features

* add sdks ([b93623d](https://github.com/seatling/sdks/commit/b93623d6bfe489631e993e113464d37c6d3abc03))


### Bug Fixes

* **core:** adapt rust core to updated cargo dependencies ([0c428a3](https://github.com/seatling/sdks/commit/0c428a3c0dbb9d1cdda3d7c83bc19bd5ceb8e83b))
* **core:** allow unused mut on stored keystore in test_core for non-windows ([2c2cf3c](https://github.com/seatling/sdks/commit/2c2cf3ca2953699d46f2b8ec85c5c9a8f1dc9c65))
* **core:** ensure deterministic zero secret for HardwareSealed tier on non-windows ([344acee](https://github.com/seatling/sdks/commit/344acee2432bd00e2a7704c3797aac8dfc46e135))
* **core:** resolve cross-platform clippy lints in platform modules and keystore ([7c79eb6](https://github.com/seatling/sdks/commit/7c79eb608d0edd1afee3a4e32364fbc910a996b4))
* **core:** sync keystore timeline for verified offline lease and setup MSVC in CI ([195694a](https://github.com/seatling/sdks/commit/195694a854e58b129fd49becbabfef6fda729bf8))
