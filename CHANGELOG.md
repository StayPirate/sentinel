# Changelog

## [0.5.0](https://github.com/StayPirate/sentinel/compare/v0.4.0...v0.5.0) (2026-08-22)


### Features

* add admin fetcher config and audit-log reads ([#306](https://github.com/StayPirate/sentinel/issues/306)) ([5e498c5](https://github.com/StayPirate/sentinel/commit/5e498c571159703229f34ae6252f3fca7814b5bc))
* add fetcher configuration mutation ([#307](https://github.com/StayPirate/sentinel/issues/307)) ([74bff8c](https://github.com/StayPirate/sentinel/commit/74bff8c58ab094043b88c505e48bb38431c4e825))
* add fetcher persistence and audit foundation ([#257](https://github.com/StayPirate/sentinel/issues/257)) ([cf6ac43](https://github.com/StayPirate/sentinel/commit/cf6ac432f41341e125299bcd5c0da49c3aece6cb))
* add generic run_fetcher task with atomic run acquisition ([#261](https://github.com/StayPirate/sentinel/issues/261)) ([19469ee](https://github.com/StayPirate/sentinel/commit/19469eeb7e63d3e830bb325ea2c842ccfbf3bf84)), closes [#242](https://github.com/StayPirate/sentinel/issues/242)
* add public fetcher observation API ([#303](https://github.com/StayPirate/sentinel/issues/303)) ([9826cf5](https://github.com/StayPirate/sentinel/commit/9826cf55049060babf29e8e5995a3154653b6473))
* add queued state to fetcher run lifecycle ([#311](https://github.com/StayPirate/sentinel/issues/311)) ([f0e5e15](https://github.com/StayPirate/sentinel/commit/f0e5e1537edde5ce894045dbe66fe4771b54c93a))
* bootstrap fetcher configs during process startup ([#265](https://github.com/StayPirate/sentinel/issues/265)) ([6a0f2ef](https://github.com/StayPirate/sentinel/commit/6a0f2ef5051cc1f963418b22e7231de8af73e38d))
* implement BaseFetcher lifecycle and registry ([#260](https://github.com/StayPirate/sentinel/issues/260)) ([1684986](https://github.com/StayPirate/sentinel/commit/168498617ae7a055c254ec0104f9a3adad803341))
* reconcile RedBeat schedule against FetcherConfig at Beat startup ([#300](https://github.com/StayPirate/sentinel/issues/300)) ([17b0394](https://github.com/StayPirate/sentinel/commit/17b039456c316c265c6a6ce16891e9b133afee7d))


### Bug Fixes

* allow Renovate custom manager to scan backend/tests/conftest.py ([#285](https://github.com/StayPirate/sentinel/issues/285)) ([529c939](https://github.com/StayPirate/sentinel/commit/529c9396b44e70a19e0faa10bee7c0fd382a3154)), closes [#284](https://github.com/StayPirate/sentinel/issues/284)
* configure explicit socket timeouts for RedBeat's Redis client ([#305](https://github.com/StayPirate/sentinel/issues/305)) ([70ba15b](https://github.com/StayPirate/sentinel/commit/70ba15b58a84b94876594b8f33476e43c306bf35)), closes [#304](https://github.com/StayPirate/sentinel/issues/304)
* dispose async engine across Celery event-loop boundaries ([#296](https://github.com/StayPirate/sentinel/issues/296)) ([ac9cfbe](https://github.com/StayPirate/sentinel/commit/ac9cfbe80cbfa336924d9f8817599b25a784d0e3)), closes [#293](https://github.com/StayPirate/sentinel/issues/293)
* finalize fetcher runs after setup failures ([#312](https://github.com/StayPirate/sentinel/issues/312)) ([6220fb2](https://github.com/StayPirate/sentinel/commit/6220fb27f4b55c978df710583a59c32defad1bca))
* persist per-run Celery hard time limit for stale detection ([#315](https://github.com/StayPirate/sentinel/issues/315)) ([ab507af](https://github.com/StayPirate/sentinel/commit/ab507afbb89e66efef57b67f5484d892373842a7)), closes [#310](https://github.com/StayPirate/sentinel/issues/310)


### Documentation

* fix contradictions in fetcher-infrastructure run() lifecycle ([#299](https://github.com/StayPirate/sentinel/issues/299)) ([64f25c8](https://github.com/StayPirate/sentinel/commit/64f25c89d07a797a52c6b1d6b195422844695832))

## [0.4.0](https://github.com/StayPirate/sentinel/compare/v0.3.0...v0.4.0) (2026-08-14)


### Features

* add identity audit persistence and service ([#155](https://github.com/StayPirate/sentinel/issues/155)) ([794c985](https://github.com/StayPirate/sentinel/commit/794c98502470fb99e53de0bd43d6091289ec852a))
* add Session and ApiKey persistence models ([#151](https://github.com/StayPirate/sentinel/issues/151)) ([eb4af4d](https://github.com/StayPirate/sentinel/commit/eb4af4dd228b1a0770aae3b9059a3fcb03bcc81a))
* **auth:** add JWT session service, logout, and cleanup task ([#158](https://github.com/StayPirate/sentinel/issues/158)) ([482c1d4](https://github.com/StayPirate/sentinel/commit/482c1d42d0603b1a1bc0e3c36bd1fb6bca3adaa6))
* **auth:** add local password login endpoint with lockout ([#162](https://github.com/StayPirate/sentinel/issues/162)) ([18c5534](https://github.com/StayPirate/sentinel/commit/18c55340140efb17f4a7b7b218298cfc2103078b)), closes [#114](https://github.com/StayPirate/sentinel/issues/114)
* **auth:** add optional authentication for public reads ([#229](https://github.com/StayPirate/sentinel/issues/229)) ([807668d](https://github.com/StayPirate/sentinel/commit/807668d17cfadf326a451f994da942c4d4407ca3))
* **auth:** add unified authentication dependencies ([#178](https://github.com/StayPirate/sentinel/issues/178)) ([a0ad9d8](https://github.com/StayPirate/sentinel/commit/a0ad9d81ac0dc449d355077898644f317f08e647))
* constrain api_key.key_hash to SHA-256 hex digest format ([#154](https://github.com/StayPirate/sentinel/issues/154)) ([3890175](https://github.com/StayPirate/sentinel/commit/3890175587cef115bc218ecb837684466de5e91c)), closes [#150](https://github.com/StayPirate/sentinel/issues/150)
* **identity:** add API key lifecycle service with audit trail ([#174](https://github.com/StayPirate/sentinel/issues/174)) ([42d53a9](https://github.com/StayPirate/sentinel/commit/42d53a916933453fbefcd41d601c30a73145e00d))
* **identity:** add API key management endpoints ([#181](https://github.com/StayPirate/sentinel/issues/181)) ([8d65fb0](https://github.com/StayPirate/sentinel/commit/8d65fb069495aab43cc46c89f59d496b13c34aa9))
* **identity:** add CLI infrastructure and user bootstrap commands ([#201](https://github.com/StayPirate/sentinel/issues/201)) ([5035e62](https://github.com/StayPirate/sentinel/commit/5035e624e42ccfe5bca96977c494b01363ef4261))
* **identity:** add password reset and unlock services ([#184](https://github.com/StayPirate/sentinel/issues/184)) ([a2c256c](https://github.com/StayPirate/sentinel/commit/a2c256c0d6ab3828345e5fc5564565d219ed8a16))
* **identity:** add remaining local identity CLI commands ([#202](https://github.com/StayPirate/sentinel/issues/202)) ([5085cf7](https://github.com/StayPirate/sentinel/commit/5085cf7e1dc82400663335da1e25a799b71bc6fb))
* **identity:** add ticket-independent admin user mutation APIs ([#198](https://github.com/StayPirate/sentinel/issues/198)) ([c656808](https://github.com/StayPirate/sentinel/commit/c65680879de71a2a6f21ece01c980bc1bcc4c597))
* **identity:** add user lifecycle create/update/reactivate services ([#183](https://github.com/StayPirate/sentinel/issues/183)) ([f5e256e](https://github.com/StayPirate/sentinel/commit/f5e256e9a19a61978ac8973e9369fc8f718b51cf))
* **identity:** add user read, profile, and identity audit APIs ([#195](https://github.com/StayPirate/sentinel/issues/195)) ([7ff84be](https://github.com/StayPirate/sentinel/commit/7ff84be0d0709d5728e3e3d3315262c7313b407b)), closes [#123](https://github.com/StayPirate/sentinel/issues/123)
* **platform:** add system settings persistence and bootstrap ([#204](https://github.com/StayPirate/sentinel/issues/204)) ([a3b960b](https://github.com/StayPirate/sentinel/commit/a3b960b0169c955a2e322a72dd921efa9d336b1c)), closes [#113](https://github.com/StayPirate/sentinel/issues/113)
* **platform:** add system settings read and audit log APIs ([#222](https://github.com/StayPirate/sentinel/issues/222)) ([80ba9d6](https://github.com/StayPirate/sentinel/commit/80ba9d6c1af639b893b090cb5e834afd0d40a3ec)), closes [#120](https://github.com/StayPirate/sentinel/issues/120)


### Bug Fixes

* align User.roles and manager_id cascade with unsupported deletion ([#153](https://github.com/StayPirate/sentinel/issues/153)) ([d58f76c](https://github.com/StayPirate/sentinel/commit/d58f76c9b5d88be8de6c5a2127c06fac80b5521d)), closes [#149](https://github.com/StayPirate/sentinel/issues/149)
* run API transaction commit before response is sent ([#165](https://github.com/StayPirate/sentinel/issues/165)) ([f376a26](https://github.com/StayPirate/sentinel/commit/f376a26373129308a50033078ef7bd8d73428301))
* trace greenlet and thread execution in coverage measurement ([#167](https://github.com/StayPirate/sentinel/issues/167)) ([ea29110](https://github.com/StayPirate/sentinel/commit/ea29110de36355c09c17daaca7ca98001c6defe0)), closes [#166](https://github.com/StayPirate/sentinel/issues/166)

## [0.3.0](https://github.com/StayPirate/sentinel/compare/v0.2.0...v0.3.0) (2026-08-03)


### Features

* add AuditEventMixin and BaseAuditLog audit trail infrastructure ([#83](https://github.com/StayPirate/sentinel/issues/83)) ([8338a71](https://github.com/StayPirate/sentinel/commit/8338a71c2b239db49ee5b5f5ba19df6c7b6751c1))
* add Celery application bootstrap with startup validation ([#80](https://github.com/StayPirate/sentinel/issues/80)) ([6db7ca5](https://github.com/StayPirate/sentinel/commit/6db7ca5e35a0b8dbec6087ed86c04253c6ccf4f1))
* add health/readiness endpoints and image assertions ([#91](https://github.com/StayPirate/sentinel/issues/91)) ([0773f95](https://github.com/StayPirate/sentinel/commit/0773f95702cde6763452987d075b5f066fdce508))
* add identity root models and static RBAC resolution ([#54](https://github.com/StayPirate/sentinel/issues/54)) ([373223b](https://github.com/StayPirate/sentinel/commit/373223b91f310198719798dcb8a24b2584dd3727))
* add shared HTTP client and TLS trust store infrastructure ([#79](https://github.com/StayPirate/sentinel/issues/79)) ([5849f98](https://github.com/StayPirate/sentinel/commit/5849f983a28c8a30f37486150c0aff06f68e3f72))
* add structured logging and request correlation ([#45](https://github.com/StayPirate/sentinel/issues/45)) ([63318c2](https://github.com/StayPirate/sentinel/commit/63318c2a974fe9abd1f5ca8b8386a2d3fbababfd))


### Bug Fixes

* eliminate release-please uv.lock race condition via extra-files ([#82](https://github.com/StayPirate/sentinel/issues/82)) ([e91b77f](https://github.com/StayPirate/sentinel/commit/e91b77f7436c9ac98213e39265220031e240c47a)), closes [#81](https://github.com/StayPirate/sentinel/issues/81)


### Documentation

* define async model factory fixture pattern ([#51](https://github.com/StayPirate/sentinel/issues/51)) ([a64a480](https://github.com/StayPirate/sentinel/commit/a64a4804ea2726eee3f7fecbbff053ada17e5099))

## [0.2.0](https://github.com/StayPirate/Sentinel/compare/v0.1.0...v0.2.0) (2026-07-30)


### Features

* add versioning strategy and release-please automation ([882c89a](https://github.com/StayPirate/Sentinel/commit/882c89ac3050273f8a5faf4cd99052a25116c5bb))
* apply testing infrastructure rollout ([c608447](https://github.com/StayPirate/Sentinel/commit/c608447821ea2fa438ff8d48840690727387a26c))
* converge Python version to 3.13 with single source of truth ([77a6aee](https://github.com/StayPirate/Sentinel/commit/77a6aee4355f992faa2d45a4122f8dc83c53edd9))
* type secret configuration fields as SecretStr ([8fd58ce](https://github.com/StayPirate/Sentinel/commit/8fd58cec6432325c0643d009ffb86167646670ed))


### Bug Fixes

* replace python-jose with PyJWT to resolve ecdsa vulnerability ([e230d23](https://github.com/StayPirate/Sentinel/commit/e230d23ef0f8b3c4fdc13e71b846a3a3379e1025))
* resolve test deprecation warning and improve dev setup ([#12](https://github.com/StayPirate/Sentinel/issues/12)) ([fa1cf0c](https://github.com/StayPirate/Sentinel/commit/fa1cf0cfd77926f4eef9256e16a8fb54684afa96))
* target sentinel-smoke project in image compose_exec fixture ([1967942](https://github.com/StayPirate/Sentinel/commit/19679425d58da8fa47d62147b412d1ca1caf09d6))


### Documentation

* add health-endpoints spec, resolve NET-DES-01 ([4b69939](https://github.com/StayPirate/Sentinel/commit/4b69939a677f11c43aa98142b63f2c5d7c33204b))
* apply CVE affected data gaps action plan (OP-1 through OP-6) ([81b86ec](https://github.com/StayPirate/Sentinel/commit/81b86ec03a5a7d17615f9751758da61c06f719f8))
* drop image-testing-setup draft, decouple smoke-test spec ([248532f](https://github.com/StayPirate/Sentinel/commit/248532fb9cc0425431be154729423f8aa162ec3b))
* resolve all 5 configuration review findings ([b817f0b](https://github.com/StayPirate/Sentinel/commit/b817f0b240af35e81ab87c122fb85d78ece14259))
* rewrite architecture.md, move operational content to deployment.md ([52b3f9b](https://github.com/StayPirate/Sentinel/commit/52b3f9baee7b2cecceee9ef635acfc0ee2925b33))
