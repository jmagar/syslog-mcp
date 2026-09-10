# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.16.0](https://github.com/dinglebear-ai/cortex/compare/v3.15.0...v3.16.0) (2026-09-10)


### Added

* **agent:** ingest file tails through the agent with stable identity ([#223](https://github.com/dinglebear-ai/cortex/issues/223)) ([a81b15d](https://github.com/dinglebear-ai/cortex/commit/a81b15d8ba24cf8911395f437f73188cf18e8d71))
* **observatory:** complete evidence-led agent delivery ([#218](https://github.com/dinglebear-ai/cortex/issues/218)) ([23b9144](https://github.com/dinglebear-ai/cortex/commit/23b9144707cd5a6eefc23c7c29d1327c5acf54a1))


### Fixed

* address post-merge concurrency review ([#211](https://github.com/dinglebear-ai/cortex/issues/211)) ([143461e](https://github.com/dinglebear-ai/cortex/commit/143461ec13d86f9503495275357f7c82af6b8ce3))
* **agent:** preserve embedded Docker log severity ([#220](https://github.com/dinglebear-ai/cortex/issues/220)) ([d9d199f](https://github.com/dinglebear-ai/cortex/commit/d9d199f1a6e81702232046d28688022f0a0d2544))
* **agent:** report the failing ssh command when a remote closes stdin early ([#226](https://github.com/dinglebear-ai/cortex/issues/226)) ([b1c1815](https://github.com/dinglebear-ai/cortex/commit/b1c1815a12da07b1778fa562ee419f912e328283))
* consolidate outstanding Cortex reliability work ([#210](https://github.com/dinglebear-ai/cortex/issues/210)) ([e8a9764](https://github.com/dinglebear-ai/cortex/commit/e8a9764910274b86a8012848054a514437260cdb))
* **deps:** bump js-yaml to 4.3.2 in the web workspace ([#228](https://github.com/dinglebear-ai/cortex/issues/228)) ([5940f6d](https://github.com/dinglebear-ai/cortex/commit/5940f6db85acd57c494dcd428f242b6d4c9b73da))
* harden Cortex contracts, recovery, and release validation ([#213](https://github.com/dinglebear-ai/cortex/issues/213)) ([d1e60c4](https://github.com/dinglebear-ai/cortex/commit/d1e60c4e805ae4be2f337105bfeec25329282eb6))
* harden graph staging coordination ([#212](https://github.com/dinglebear-ai/cortex/issues/212)) ([63df9d6](https://github.com/dinglebear-ai/cortex/commit/63df9d6223d51db93a17ce05f6d1d32ef73b3066))
* **reflection:** restore Codex skill evidence and app-server assessments ([#219](https://github.com/dinglebear-ai/cortex/issues/219)) ([5fd4c82](https://github.com/dinglebear-ai/cortex/commit/5fd4c82dd500ee6809564128cea3c330d0169e29))
* **runtime:** release syslog listeners on shutdown ([#217](https://github.com/dinglebear-ai/cortex/issues/217)) ([3e4929d](https://github.com/dinglebear-ai/cortex/commit/3e4929d008b82a7834f92950a6a07e13b4ace7da))

## [3.15.0](https://github.com/dinglebear-ai/cortex/compare/v3.14.0...v3.15.0) (2026-08-25)


### Added

* **observatory:** add OTLP metrics, query services, and web foundation ([#202](https://github.com/dinglebear-ai/cortex/issues/202)) ([cf605af](https://github.com/dinglebear-ai/cortex/commit/cf605af84051aa9671d3af8bbb0d056ec7788d66))


### Fixed

* **ci:** unblock the merge gate — container probe and cargo-deny ([#205](https://github.com/dinglebear-ai/cortex/issues/205)) ([04166c4](https://github.com/dinglebear-ai/cortex/commit/04166c4e8e4b2cb593d8b1e5d7d29a5d4470ae03))
* stop misclassifying SQLite pool timeouts as permanent failures ([#204](https://github.com/dinglebear-ai/cortex/issues/204)) ([1118d65](https://github.com/dinglebear-ai/cortex/commit/1118d658995035bb4ad17fe2daa28a7c518a6b40))

## [3.14.0](https://github.com/dinglebear-ai/cortex/compare/v3.13.2...v3.14.0) (2026-08-20)


### Added

* add W16 artifact evidence foundation ([#198](https://github.com/dinglebear-ai/cortex/issues/198)) ([d232d82](https://github.com/dinglebear-ai/cortex/commit/d232d82bdafc1978fd389cf1f134f29631febc4c))
* **agent-observatory:** ingest OTLP traces and normalize metrics ([#200](https://github.com/dinglebear-ai/cortex/issues/200)) ([154474a](https://github.com/dinglebear-ai/cortex/commit/154474a17531f3281a18589ebc9bfeeddb7a8686))
* **agent-observatory:** make projector cursors transactional ([#195](https://github.com/dinglebear-ai/cortex/issues/195)) ([74eaa15](https://github.com/dinglebear-ai/cortex/commit/74eaa151dc5b1282def8c3a6a43db6e46b50c929))


### Fixed

* harden actionable error-signature reads ([#199](https://github.com/dinglebear-ai/cortex/issues/199)) ([64098b3](https://github.com/dinglebear-ai/cortex/commit/64098b3fa4471837aec82a6063cc625f02a61f78))


### Changed

* harden Cortex hot paths and eliminate audit debt ([#196](https://github.com/dinglebear-ai/cortex/issues/196)) ([ecbd33b](https://github.com/dinglebear-ai/cortex/commit/ecbd33b8383313c84c5e71a97c06f3a4175e0c6c))

## [3.13.2](https://github.com/dinglebear-ai/cortex/compare/v3.13.1...v3.13.2) (2026-08-10)


### Fixed

* **agent:** verify Windows task restart ([#191](https://github.com/dinglebear-ai/cortex/issues/191)) ([74f6e36](https://github.com/dinglebear-ai/cortex/commit/74f6e36624948959618306304bc232457f4d7fb5))

## [3.13.1](https://github.com/dinglebear-ai/cortex/compare/v3.13.0...v3.13.1) (2026-08-09)


### Fixed

* **agent:** preserve Windows supervisor ownership ([#189](https://github.com/dinglebear-ai/cortex/issues/189)) ([9004bae](https://github.com/dinglebear-ai/cortex/commit/9004baec3f5b8d927424333031cb8e8363998204))

## [3.13.0](https://github.com/dinglebear-ai/cortex/compare/v3.12.0...v3.13.0) (2026-08-09)


### Added

* **agent:** propagate server releases to Windows fleet ([#187](https://github.com/dinglebear-ai/cortex/issues/187)) ([4c9ca71](https://github.com/dinglebear-ai/cortex/commit/4c9ca711fe21215fd5f9eb50b71fa2c74424fc44))

## [3.12.0](https://github.com/dinglebear-ai/cortex/compare/v3.11.3...v3.12.0) (2026-08-09)


### Added

* add cursor event feed and Docker lifecycle forwarding ([#185](https://github.com/dinglebear-ai/cortex/issues/185)) ([26a85b8](https://github.com/dinglebear-ai/cortex/commit/26a85b89c96b7f9213af06cdf7ac6903f4667c63))
* agent observatory schema foundation + transcript-forwarding env rename ([#173](https://github.com/dinglebear-ai/cortex/issues/173)) ([61aa50a](https://github.com/dinglebear-ai/cortex/commit/61aa50ad4e59461a281b29bd559e4a90fa730a26))
* implement Agent Observatory foundation, projection, and Git observation ([#160](https://github.com/dinglebear-ai/cortex/issues/160)) ([6d3031d](https://github.com/dinglebear-ai/cortex/commit/6d3031dc669624560b7ec29e88206f26189a3b15))


### Fixed

* **ci:** pin kache 0.13.0 to match the runner fleet ([#178](https://github.com/dinglebear-ai/cortex/issues/178)) ([04cbd51](https://github.com/dinglebear-ai/cortex/commit/04cbd511a39ac8def9d2d8ba4e7ddcec24eb4f94))
* **ci:** remove expression syntax from the s3-endpoint description ([#184](https://github.com/dinglebear-ai/cortex/issues/184)) ([74c2db7](https://github.com/dinglebear-ai/cortex/commit/74c2db759421a4d2d4fcce04c1b40b4ca70e34e8))
* **ci:** remove leaked internal identifiers from setup-rust-kache ([#183](https://github.com/dinglebear-ai/cortex/issues/183)) ([02e3e7f](https://github.com/dinglebear-ai/cortex/commit/02e3e7fc56e71a2c5281749fd4e5a15e1c6d6e5e))
* **ci:** require complete Kache S3 configuration ([#186](https://github.com/dinglebear-ai/cortex/issues/186)) ([d50e1af](https://github.com/dinglebear-ai/cortex/commit/d50e1aff7af6f8a9d098bd6a16993992385a9919))
* **ci:** route .github/actions changes through the full CI matrix ([#180](https://github.com/dinglebear-ai/cortex/issues/180)) ([b8e6900](https://github.com/dinglebear-ai/cortex/commit/b8e6900092ab7139166f43ad9adb55d7c1c3fcb5))
* **mcpb:** add Windows bundle packaging ([#164](https://github.com/dinglebear-ai/cortex/issues/164)) ([a304469](https://github.com/dinglebear-ai/cortex/commit/a304469610a1f9ca98bf725b3f7668d5aa58f359))
* **mcp:** centralize Registry publication ([#171](https://github.com/dinglebear-ai/cortex/issues/171)) ([b731ec3](https://github.com/dinglebear-ai/cortex/commit/b731ec34a14f3a8a606292c7d90124f3125319c9))
* **mcp:** return structured errors and exact contracts ([#170](https://github.com/dinglebear-ai/cortex/issues/170)) ([287417c](https://github.com/dinglebear-ai/cortex/commit/287417cb72cfc529cf30cd8c33678a8cb909326c))


### Changed

* **ci:** emit line-tables-only debuginfo in dev builds ([#182](https://github.com/dinglebear-ai/cortex/issues/182)) ([1094384](https://github.com/dinglebear-ai/cortex/commit/1094384f063044c998c023d5de0144f0e16c3bc2))


### Chores

* adopt AGPL-3.0-only with commercial licensing ([#176](https://github.com/dinglebear-ai/cortex/issues/176)) ([6afa01a](https://github.com/dinglebear-ai/cortex/commit/6afa01ad46594f9ad0e7bd519cdbc44b46664002))
* scrub internal network identifiers ([#174](https://github.com/dinglebear-ai/cortex/issues/174)) ([3a91a07](https://github.com/dinglebear-ai/cortex/commit/3a91a07a3ca546cde40d9553a8418c14af86ebe3))


### CI

* audit concurrency, coverage gating, release cache, and cron scoping ([#177](https://github.com/dinglebear-ai/cortex/issues/177)) ([7c35d1f](https://github.com/dinglebear-ai/cortex/commit/7c35d1f4d3d1bd610349592bb1ad2a397a77dc5f))
* record what `RUSTC_WRAPPER` resolves to before the build ([#181](https://github.com/dinglebear-ai/cortex/issues/181)) ([4318085](https://github.com/dinglebear-ai/cortex/commit/4318085021b55ad173b8b6a84b10cd898df370a7))


### Documentation

* add the Agent Observatory implementation plan and align the rmcp 3.0.0-beta.2 toolchain ([#172](https://github.com/dinglebear-ai/cortex/issues/172)) ([f2cb986](https://github.com/dinglebear-ai/cortex/commit/f2cb9869a2fce06c93a4cd42acfe4a6fc30a0b1d))

## [3.11.3](https://github.com/dinglebear-ai/cortex/compare/v3.11.2...v3.11.3) (2026-08-03)


### Fixed

* **ci:** preserve existing Kache config ([#159](https://github.com/dinglebear-ai/cortex/issues/159)) ([f721a50](https://github.com/dinglebear-ai/cortex/commit/f721a50577c961aed00f48376a5bfb96c9c53966))
* **release:** invoke cortex in container smoke ([#165](https://github.com/dinglebear-ai/cortex/issues/165)) ([5ca85ca](https://github.com/dinglebear-ai/cortex/commit/5ca85ca875da4ad7fddb22c2da10abc3726b498a))
* **release:** keep registry description schema-compliant ([#169](https://github.com/dinglebear-ai/cortex/issues/169)) ([0cc5b13](https://github.com/dinglebear-ai/cortex/commit/0cc5b13cd92503fb2fb0dcd6b0b7b97e2f31da22))
* **release:** publish MCP metadata with dinglebear.ai ([f018f0f](https://github.com/dinglebear-ai/cortex/commit/f018f0fab7e189352226c4a76d2713107f2bf255))

## [3.11.2](https://github.com/dinglebear-ai/cortex/compare/v3.11.1...v3.11.2) (2026-08-02)


### Fixed

* **agent:** harden self-update without blocking heartbeats ([#156](https://github.com/dinglebear-ai/cortex/issues/156)) ([35ce512](https://github.com/dinglebear-ai/cortex/commit/35ce51257930718bdf62bfb43ffdf7c67d48dd76))
* **ci:** centralize release-only container publishing ([#149](https://github.com/dinglebear-ai/cortex/issues/149)) ([3d75d10](https://github.com/dinglebear-ai/cortex/commit/3d75d109cc3531d1b18c9d32c4059566651cd863))
* **ci:** drop the stale gitleaks contract assertions ([fd0525a](https://github.com/dinglebear-ai/cortex/commit/fd0525aa2c28cf3fcc6aa0edc759a19daa9e6336))
* **ci:** enforce documentation and identity contracts ([ab5ef39](https://github.com/dinglebear-ai/cortex/commit/ab5ef392329735990a55e1f3819b69f19ea36753))
* correct at-limit CRLF framing and address PR review findings ([76a9814](https://github.com/dinglebear-ai/cortex/commit/76a9814fc709de2327323616540b18dcd4a2dcf9))
* enforce repository contracts and reduce query module debt ([aa7e991](https://github.com/dinglebear-ai/cortex/commit/aa7e991d303d1ddf60cfe97435baa35c30e784b6))
* **filetail:** distinguish append growth from replacement ([#161](https://github.com/dinglebear-ai/cortex/issues/161)) ([337f608](https://github.com/dinglebear-ai/cortex/commit/337f608ff5dea34a66a1b1d53626c3908a5918cb))
* **filetail:** preserve reconciled checkpoint on first open ([#157](https://github.com/dinglebear-ai/cortex/issues/157)) ([2086823](https://github.com/dinglebear-ai/cortex/commit/20868234a016ec33d54c9d7e00f2f2421e04dae5))
* finish the ghcr namespace migration and bound Gemini parse warnings ([1bf8257](https://github.com/dinglebear-ai/cortex/commit/1bf8257372e5eb73d21d72ef80e65b201fe53eeb))
* finish the ghcr namespace migration and bound Gemini parse warnings ([98de4dd](https://github.com/dinglebear-ai/cortex/commit/98de4dddc08bc37ab2ce64f8416a33dd5a0dbeec))
* harden transcript warnings, hostname resolution, and TCP framing ([78f11d1](https://github.com/dinglebear-ai/cortex/commit/78f11d1f46edfcdb66f7c584c04fa58d14da2563))
* **inventory:** preserve results and collect DNS settings ([#154](https://github.com/dinglebear-ai/cortex/issues/154)) ([d54194e](https://github.com/dinglebear-ai/cortex/commit/d54194e09af942fe5a51ca316cf55965b66effb0))
* **npm:** resync the packaged README with the repo README ([c11391d](https://github.com/dinglebear-ai/cortex/commit/c11391d457c9a2b773283f645b630e62eb364155))
* publish npm launcher as @dinglebear/cortex ([7b36683](https://github.com/dinglebear-ai/cortex/commit/7b366835e8fead61fcbf107a8909f732e7518286))
* **release:** use explicit npm version updater ([#158](https://github.com/dinglebear-ai/cortex/issues/158)) ([aed693b](https://github.com/dinglebear-ai/cortex/commit/aed693becb3a5b31294481a514c6d770e2cff7f2))
* **release:** use scalar Cargo package versions ([#162](https://github.com/dinglebear-ai/cortex/issues/162)) ([b951591](https://github.com/dinglebear-ai/cortex/commit/b9515913c37aecd1afb7f783edfe724578de56a8))
* **security:** patch quinn and restrict workflow tokens ([94bf0de](https://github.com/dinglebear-ai/cortex/commit/94bf0def9c9420cce3f82a3c1ba5cf3f2d59f207))
* **xtask:** preserve pre-push toolchain environment ([8d495b9](https://github.com/dinglebear-ai/cortex/commit/8d495b98f9f88887bf77f57a2b037927cd54e672))


### Changed

* **db:** extract host queries ([dc6c693](https://github.com/dinglebear-ai/cortex/commit/dc6c693c9409301c30db74945cafd21af79f058f))

## [3.11.1](https://github.com/jmagar/cortex/compare/v3.11.0...v3.11.1) (2026-07-17)


### Fixed

* **notifications:** suppress repeat silence outages ([5e98246](https://github.com/jmagar/cortex/commit/5e982465c489d720192a7046cd599683c4384d39))
* preserve heartbeat graph resolution ([6eb8c78](https://github.com/jmagar/cortex/commit/6eb8c78c570d0c0e90ff3012009e97736eedda8a))
* repair storage graph and fleet maintenance ([7a04504](https://github.com/jmagar/cortex/commit/7a04504ba4830a3e46d4f97da29b716b5c04a4e5))
* tolerate bounded SSH probe stalls ([29ac736](https://github.com/jmagar/cortex/commit/29ac7365272bf2a5bfaf288c9616e3ce2ba69685))

## [3.11.0](https://github.com/jmagar/cortex/compare/v3.10.0...v3.11.0) (2026-07-17)


### Added

* canonical entity resolution for the investigation graph ([#133](https://github.com/jmagar/cortex/issues/133)) ([ac913c7](https://github.com/jmagar/cortex/commit/ac913c7e09d635e114cfee519e4751b20a38f703))
* **mcp:** make query widget usable on hosts without resources/read ([#139](https://github.com/jmagar/cortex/issues/139)) ([ff696b9](https://github.com/jmagar/cortex/commit/ff696b9105145d960af4bfc8694821ad78ee982f))
* **notifications:** heartbeat-silence and stream-silence fleet alerts ([#140](https://github.com/jmagar/cortex/issues/140)) ([8e4ec60](https://github.com/jmagar/cortex/commit/8e4ec6031072505caef2f8a991d9ae25e18f1896))


### Fixed

* bump opentelemetry-proto to 0.32 to patch opentelemetry_sdk CVE ([#136](https://github.com/jmagar/cortex/issues/136)) ([1b44d72](https://github.com/jmagar/cortex/commit/1b44d72c3f32f693da7910cbf18611d381dbabb1))
* OTLP hardening follow-ups from PR [#136](https://github.com/jmagar/cortex/issues/136) review (4 beads) ([#137](https://github.com/jmagar/cortex/issues/137)) ([9b5a6c7](https://github.com/jmagar/cortex/commit/9b5a6c7a98430ff3da5af4a67639d6bf36687e66))
* remediate live CLI sweep failures ([62d0178](https://github.com/jmagar/cortex/commit/62d0178a956f99507920162b954890bf7c97e6c9))
* repair live CLI service calls ([7d7f683](https://github.com/jmagar/cortex/commit/7d7f6838652054bf1070b351eb291bafd0a6f288))

## [3.10.0](https://github.com/jmagar/cortex/compare/v3.9.0...v3.10.0) (2026-07-13)


### Added

* add ingestion health to doctor ([b9a4f5f](https://github.com/jmagar/cortex/commit/b9a4f5f04d0d0a4338ff50542d5bf8edd481cbb0))


### Fixed

* **ci:** declare mise-managed workflow tools ([bf7864b](https://github.com/jmagar/cortex/commit/bf7864be540d5ab2d5ad048aa760dfadf8c693f7))
* **ci:** use prebuilt cargo tool installers ([4e42058](https://github.com/jmagar/cortex/commit/4e4205890191b34b23939ede8fba5b2c81571394))
* harden cargo rustc wrapper test path ([0fe6be4](https://github.com/jmagar/cortex/commit/0fe6be45cb321c78b73561065af6da71196bfefe))
* respect dynamic cargo job allocation ([2e10024](https://github.com/jmagar/cortex/commit/2e10024d513266aec2a960ac1f24a57b32763ed5))
* route rust builds through sccache wrapper ([1fe67e3](https://github.com/jmagar/cortex/commit/1fe67e396d2293c057ac98ebbc99b63d03eaa9e1))

## [3.9.0](https://github.com/jmagar/cortex/compare/v3.8.0...v3.9.0) (2026-07-11)


### Added

* forward agent activity into cortex ([9633617](https://github.com/jmagar/cortex/commit/963361734b7ad8504d0923e0dbc98201ae5072f1))

## [3.8.0](https://github.com/jmagar/cortex/compare/v3.7.2...v3.8.0) (2026-07-11)


### Added

* add cortex npm launcher distribution ([a78b070](https://github.com/jmagar/cortex/commit/a78b07074ee3d6262b3c6aae19ddd3466a9cded2))
* **cli:** add cortex status command ([d705740](https://github.com/jmagar/cortex/commit/d7057403eb911e379f78083085f8e5f1ceedb92f))
* forward agent activity into cortex ([9633617](https://github.com/jmagar/cortex/commit/963361734b7ad8504d0923e0dbc98201ae5072f1))
* set up release-please for versioning and changelog automation ([#125](https://github.com/jmagar/cortex/issues/125)) ([4614d0c](https://github.com/jmagar/cortex/commit/4614d0c039c1f0561b004c7679beba1356b03ff5))
* **setup:** install cortex-backup systemd timer during setup repair ([afb068b](https://github.com/jmagar/cortex/commit/afb068bafb0e5a4692aa646f29148f4a9322f137))
* **skills:** add cortex-session-search skill ([53cfc93](https://github.com/jmagar/cortex/commit/53cfc939446b3b33f4a27c1b08121c97781674c3))
* **skills:** add hook/incident/topology skills, drop cortex- prefix from skill dirs ([#129](https://github.com/jmagar/cortex/issues/129)) ([3bb8d5e](https://github.com/jmagar/cortex/commit/3bb8d5efbafbff91fc966d6d3d1ecc2d146da048))


### Fixed

* **ci:** switch OpenWiki to local openai-compatible proxy ([fa01ba9](https://github.com/jmagar/cortex/commit/fa01ba9d7a1382bdaead58eccfaa314fc1292ef8))
* **config:** auto-adjust recovery_db_size_mb when max_db_size_mb is raised ([dc6b34b](https://github.com/jmagar/cortex/commit/dc6b34bf9d37869c740afe238a17637af8d72ca2))


### Changed

* **skills:** enhance cortex-session-search triggers and examples ([da0219f](https://github.com/jmagar/cortex/commit/da0219fa05ea99d1adf16c80868bcad4207c1d5e))

## [Unreleased]


### Licensing

- Relicense Dinglebear-owned original work under AGPL-3.0-only and document separate commercial licensing; third-party material retains its original terms.

## [3.9.1] - 2026-07-12

## [3.8.1] - 2026-07-09

### Fixed

- Synced the npm package README with the repository README so the npm package page shows the full repo documentation.

## [3.8.0] - 2026-07-08

### Added

- Three new plugin skills filling gaps in the assessment/investigation skill family: `hook-friction-assessment` (analyzes `hook_investigate` evidence bundles, mirroring the existing mcp/skill friction-assessment pattern), `incidents` (triage for `unaddressed_errors`, `ack_error`/`unack_error`, `notifications_recent`, `similar_incidents`, `incident_context`), and `topology` (homelab topology/correlation queries via `map`, `host_state`, `fleet_state`, `correlate`, `correlate_state`, `graph`).

### Changed


- Renamed all plugin skill directories to drop the redundant `cortex-` prefix (e.g. `cortex-troubleshoot` → `troubleshoot`), updating the `name:` frontmatter, sibling cross-references, `agents/openai.yaml` prompts, and the Rust `include_str!`/`SKILL_NAME` constants that embed three of these skills (`frustration-assessment`, `mcp-friction-assessment`, `skill-improvement-assessment`) into the binary at compile time.

### Removed

- Removed the `cortex-dr` and `cortex-deploy-dropins` plugin skills. `cortex-troubleshoot` (now `troubleshoot`) inlines the former's health-check description directly; rsyslog drop-in deployment is now a manual, documented process (see `docs/contracts/forwarder-dropins.md`) rather than an automated skill workflow.

## [3.7.2] - 2026-07-07

### Fixed

- `cortex setup shell agent install`/`check` now run the `cortex --version` validation subprocess on the blocking thread pool instead of the async runtime, avoiding a stalled Tokio worker thread for the subprocess's duration.
- `import_agent_command_records` now dedupes agent-command spool entries with a single batch query against already-inserted rows plus an in-batch seen-set, closing both the cross-call check-then-insert race and a same-batch duplicate gap the prior per-record loop had.
- Added a regression test covering the full `serve_mcp()` router chain (`mcp`, `api`, OTLP, heartbeat, agent-command, and web-app routers merged together) to catch route-collision panics that only surface at runtime.

## [3.7.1] - 2026-07-07

### Fixed

- The heartbeat agent's `reqwest::Client` now carries a 30s request timeout (matching the one added to the agent-command spool forwarding client in #123), so a remote Cortex that's hung rather than down fails fast and retries instead of blocking the heartbeat loop indefinitely.

## [3.7.0] - 2026-07-06

### Added

- CLI grammar rename: `cortex ingest agent-command {ingest-spool|wrap}` is now `cortex ingest shell user {index|atuin-index}` (human-typed shell history) and `cortex ingest shell agent {index|wrap}` (AI-agent-issued command capture), matching `cortex ingest shell`'s existing nesting style. The old `ingest agent-command ingest-spool`/`wrap` grammar is still accepted as a deprecated alias so already-deployed wrapper scripts and systemd timers are never bricked by this rename.
- `cortex setup agent-command install|remove|check` is renamed to `cortex setup shell agent install|remove|check` (no back-compat alias — this is an interactively-typed operator command, not embedded in any unattended artifact).
- New `cortex setup shell completions install|remove|check` — installs the zsh completion script to `~/.local/share/cortex/completions/_cortex`, alongside the existing `cortex completions zsh` (which still just prints the script to stdout).
- `cortex ingest shell agent index` gains `--server URL` / `--token TOKEN`: instead of writing to the local SQLite database, the spool is forwarded over HTTP to a remote Cortex's new `POST /v1/agent-commands` endpoint. The spool is truncated only after a successful forward, so a network failure leaves it intact for the next attempt (mirroring the heartbeat agent's retry-safe pattern).
- New `POST /v1/agent-commands` server endpoint (mounted on the shared HTTP listener, port 3100) accepts forwarded agent-command batches from satellite hosts, deduping the same way local ingest does. Capped at 1 MiB body size and 5,000 records per batch; inserted rows record the verified TCP peer IP (`forwarded_from_peer_ip` in `metadata_json`) alongside the client-claimed `hostname`/`agent` fields.
- `cortex doctor` gains a `stale-agent-command-units` check that scans `systemctl --user` service/timer units for `ExecStart=` lines still invoking the pre-rename `agent-command ingest-spool` grammar, plus `--fix`/`--yes` flags (both required together) to disable flagged units.

## [3.6.5] - 2026-07-04

### Fixed

- `skill_incident_evidence.rs`/`mcp_incident_evidence.rs`/`hook_incident_evidence.rs` all routed exact `incident_id` investigation lookups through their `search_ai_*_incidents` function with `limit: Some(100)`, then filtered the returned top-100-by-priority candidates client-side for the matching id — an incident ranked below the top 100 silently returned empty evidence even though it existed. Added an `incident_id` field to `Ai*IncidentParams` so the full computed incident set (bounded only by the event-candidate cap, not an incident-count cap) is filtered before priority-ranked truncation.
- The same three modules' "nearby non-AI logs in the correlation window" query filtered only by `timestamp`, with no `hostname` scope, so an incident on one host could pull in unrelated log rows from a different host active in the same time window. Added `hostname = ?` to the query, bound to the incident's own host.
- `HookIncidentEvidence` (app model) passed `hook_events` straight through as the db-layer `AiHookEventEntry` type instead of translating to the app-level `HookEventEntry`, unlike every other evidence vector on the same struct. `derive_hook_incident_findings` now takes `&[HookEventEntry]` to match.

## [3.6.4] - 2026-07-03

### Fixed (CodeRabbit review round)

- `hook_invoked_too_often` findings always reported "medium" confidence via a hardcoded `confidence_for(2)`; now scales with the actual invocation count like every other hook failure mode.
- `HookIncident::has_runtime_evidence` used `.any()` against its own doc ("true when *every* hook event... is `runtime_transcript`"), so a mixed runtime/config-evidence incident was incorrectly reported as proven-executed. Changed to `.all()`.
- `idx_ai_hook_events_unique` omitted `hostname`, so two different hosts collecting identical `config_inventory`/`trusted_hash_state` rows (both `ai_session_id = NULL`) at the same timestamp would collide under `INSERT OR IGNORE` and silently drop one host's row. Added `hostname` to the index (safe — this migration is unreleased).
- `LlmEvidenceCounts.truncated` in `cortex assess hooks` only considered signal-anchor/transcript truncation, undercounting the audit signal for `hook_events_truncated`/`nearby_tool_calls_truncated`/`nearby_logs_truncated`/`nearby_errors_truncated`, all of which are part of the same serialized evidence bundle.
- `cortex sessions hook-events`/`hooks-backfill` reported unknown flags with a bare error instead of the shared `suggest::unknown_option` "did you mean" UX every other new parser in this PR uses.
- `scripts/smoke-test.sh`'s `hook_investigate` probe passed an unsupported `hook=` filter key; `AiHookInvestigateRequest` uses `#[serde(deny_unknown_fields)]` and only accepts `hook_name`/`hook_event`/`hook_source`, so this call was being rejected. Fixed to `hook_name=`.
- `tool_hook_events` (MCP) was missing the `tracing::debug!` completion log its sibling `tool_hook_incidents`/`tool_hook_investigate` handlers both emit.
- `with_temp_home` in `hook_config_tests.rs` only restored `$HOME` on the success path; a panic inside the test body left the process-global `$HOME` pointed at a dropped temp dir for the rest of the test binary. Switched to an RAII guard.
- Docs: `CLAUDE.md`'s action count/table and `docs/api.md`'s route counts were stale after the hook actions landed (54→57 actions; table was missing `mcp_*`/`hook_*` rows entirely; route total 59→63; "AI session queries (9)" section header now says (14) to match its actual row count); `docs/api.md`'s hook_events row still cited migration 39 instead of 40.

Not fixed (tracked separately — pre-existing patterns shared with `skill_incident_evidence.rs`/`mcp_incident_evidence.rs`, not specific to this PR): `incident_id` lookups in `hook_incident_evidence.rs` are still capped by the top-100 candidate search even when an exact ID is given, and `nearby_logs` correlation doesn't scope by `hostname`. See follow-up task.

## [3.6.2] - 2026-07-03

### Added

- MCP event tracking (GH #104), mirroring GH #94's skill-event-tracking shape for MCP/tool-call events end to end:
  - A new `ai_mcp_events` table (migration 39) normalizes MCP/tool-call events, indexed against the planned query filter surface (`mcp_server`/`mcp_tool` grouping, `tool_name` lookup, session tuple, error filter).
  - `src/scanner/mcp_events.rs` parses Claude `tool_use`/`tool_result` and Codex `function_call`/`function_call_output` payloads into a normalized `ExtractedMcpEvent` shape; `mcp__<server>__<tool>` naming is the only authoritative MCP classification signal, with everything else recorded as a general tool-call row (`mcp_server = NULL`). Fixed a real extraction gap during TDD: Claude `tool_use` content items and Codex `function_call`/`function_call_output` payloads carry no free-text field, so `extract_message()` previously returned empty and `parse_line` silently dropped these rows before MCP extraction ever saw them — both parsers now emit a short synthetic summary so the row is ingested, with the full structured payload available via `raw_value`.
  - `src/db/mcp_events.rs`/`src/db/mcp_incidents.rs`/`src/db/mcp_incident_evidence.rs` provide insert/list, incident grouping (`(mcp_server, mcp_tool, ai_tool, ai_project, ai_session_id, hostname, window_bucket)`, scored/sorted via `f64::total_cmp`), and bounded evidence bundles. Fixed a real idempotency bug during TDD: SQLite never treats two `NULL`s as equal in a `UNIQUE` constraint, so a plain `UNIQUE(...)` table constraint over the dedupe key (which includes a nullable `ai_session_id`) silently let duplicate sessionless rows back in — replaced with a `UNIQUE` index over `COALESCE(ai_session_id, '')`.
  - Six deterministic MCP incident anchor signals (`src/app/mcp_signal_detectors.rs`): `repeated_call_failure`, `timeout_or_rate_limit`, `auth_or_permission_failure`, `schema_or_validation_error`, `unknown_tool_or_server`, `user_correction_after_tool_call`.
  - Deterministic, rule-based MCP incident findings (`src/app/mcp_incident_findings.rs`, no DB/LLM calls): `wrong_mcp_tool_selected`, `mcp_server_unavailable`, `mcp_auth_or_permission_failure`, `mcp_schema_mismatch`, `mcp_timeout_or_rate_limit`, `mcp_result_misinterpreted`, `missing_mcp_discovery_step`, `tool_surface_confusion`, plus `unknown`.
  - New MCP actions `mcp_events`, `mcp_incidents`, `mcp_investigate` (all `cortex:read`), plus `cortex sessions mcp-events[ backfill]|mcp-incidents|mcp-investigate` CLI commands. `mcp_investigate` resolves server/tool-first, mirroring `skill_investigate`'s skill-first resolution rule.
  - `src/scanner.rs` threads a parallel `ChunkMcpSource` side channel through `flush_chunk` (mirroring `ChunkSkillSource`), extracting and inserting `ai_mcp_events` in the same transaction as the log batch insert.
  - Bounded, idempotent, single-flight backfill (`src/app/services/mcp_backfill.rs`) scans the `raw` column (the original transcript JSON, not the scrubbed `message` summary) to catch up rows ingested before this phase shipped.
  - `cortex assess mcp` — CLI-only, LLM-guarded MCP-incident assessment mirroring `cortex assess skill`: resolves the highest-priority (or all, with `--all`) matching MCP incident and runs the guarded Gemini assessment through `LlmRunner`. A new embedded `cortex-mcp-friction-assessment` skill produces the assessment write-up. LLM assessment is CLI-only by design — `mcp_assess` is never exposed as an MCP action or REST route, and `--http` is rejected unless `--no-llm` is also passed. `cortex sessions mcp-assess <server-or-tool>` is a low-level alias forwarding to the same dispatch function.

## [3.6.3] - 2026-07-03

### Added

- `ai_hook_events` tracking plus a `cortex assess hooks` command (GH #105, split from GH #94). Adds an end-to-end hook-intelligence subsystem that distinguishes runtime-proven hook execution from configuration/trust-state inventory:
  - New normalized `ai_hook_events` table (schema migration 40, `src/db/pool.rs`) with a nullable `log_id` (config-inventory rows have no transcript log), an `evidence_kind` column (`runtime_transcript` / `config_inventory` / `trusted_hash_state`, with `log_correlation` / `side_effect_inference` reserved), and a content-based `UNIQUE(ai_tool, ai_session_id, hook_event, hook_name, timestamp, evidence_kind)` idempotency key. Migration number 40 (not 39) because GH #104's `ai_mcp_events` merged to main first and already claimed migration 39 — both PRs were developed in parallel against the same pre-#104 base and independently picked the same next-available number.
  - Claude runtime hook-attachment parser (`src/scanner/hook_events.rs`): extracts `attachment.type = hook_*` rows (`hookName`, `hookEvent`, `command`, `exitCode`, `durationMs`, redacted+bounded `stdout`/`stderr` previews, persisted-output pointer). Unknown `hook_*` variants map to an `unknown` status rather than erroring. Extraction is wired into the SAME transcript-ingest transaction as skill events, reusing the already-parsed Claude JSON value (no second parse). No Codex runtime-hook parser ships — no structured Codex runtime shape is observed yet.
  - Config-inventory collectors (`src/hook_config.rs`): read local host `~/.claude/settings.json`, `~/.codex/hooks.json`, and `~/.codex/config.toml [hooks.state]` into `config_inventory` / `trusted_hash_state` rows with a dedicated `configured` status. A configured/trusted hook is never treated as proof of execution.
  - Hook incident detection (`src/db/hook_incidents.rs`) groups events by `(hook_event, hook_name, hook_source, ai_tool, ai_project, ai_session_id, hostname, window_bucket)`, derives six deterministic anchors (`hook_failed`, `hook_timed_out`, `hook_output_parse_error`, `hook_invoked_too_often`, `user_correction_after_hook`, and same-session `hook_not_invoked`), scores/sorts with `f64::total_cmp`, and exposes `has_runtime_evidence` per incident. Evidence bundles (`src/db/hook_incident_evidence.rs`) and deterministic findings (`src/app/hook_incident_findings.rs`) carry an explicit `evidence_basis` string stating whether an incident rests on runtime or config/trust-state evidence.
  - `cortex assess hooks [--hook NAME] [--hook-event EVENT] [--since ...] [--project ...] [--tool ...] [--all|--limit N] [--no-llm] [--collect-config]` CLI: deterministic findings first, optional guarded Gemini assessment via `LlmRunner::run` (CLI-only — MCP/REST never invoke the LLM), and a live `--collect-config` host inventory collect-then-assess. Output always states the runtime-vs-config evidence basis.
  - Read surfaces: MCP actions `hook_events` / `hook_incidents` / `hook_investigate`, REST routes `/api/sessions/hooks|hook-incidents|hook-investigate`, and CLI `cortex sessions hook-events` / `cortex sessions hooks-backfill` (bounded, single-flight, idempotent backfill over the Claude runtime path).

### Fixed (post-review)

- Secret redaction on hook stdout/stderr/command previews missed JSON-encoded secrets (e.g. `{"api_key":"sk-..."}`) and bare JSON-string secrets (e.g. stdout is literally `"sk-..."`, quotes included) — the shared `redact_secrets` heuristic tokenizes on whitespace, so neither shape ever starts with a known prefix once JSON-quoted. Added tree-walking redaction (`redact_json_value_strings`, moved to `src/assessment.rs`) plus a bare-string match arm, and applied it to `hook_command` (which previously had no redaction at all) alongside stdout/stderr.
- Missing `hostname` index on `ai_hook_events` forced a full table scan for the documented `--hostname` filter.
- `hook_invoked_too_often`'s threshold (10) was measured at session-window granularity but justified with a single-tool-call rationale, false-positiving on ordinary busy coding sessions; raised to 30.
- Redacting `hook_command` before its control-character rejection check let `redact_secrets`'s whitespace-tokenize-and-rejoin silently launder out whitespace-class control characters (tab, `\v`, `\f`) before the check ever saw them, so a command that should have been rejected was instead accepted with the control character quietly gone. Reordered so rejection runs on the raw text first.
- An attempt to make repeated `--collect-config` runs idempotent by truncating the collection timestamp to the day boundary was found, via a direct DB test, to also silently drop genuine same-day `trusted_hash` rotations (the unique index's dedupe key has no content-bearing column). Reverted to full-precision timestamps — losing a real trust-hash rotation is worse than the duplicate-row growth the truncation was solving; content-aware deduplication is a better fix, left as a follow-up.

## [3.6.1] - 2026-07-03

### Fixed

- `cortex --help`/`cortex setup --help` was missing a usage line for the `sessions-watch-health-check` subcommand added in 3.6.0, even though every sibling `setup` subcommand documents its own line.

### Changed

- Split `src/setup/resolve.rs` and `src/setup/sessions_watch_legacy.rs` off their tests into dedicated `resolve_tests.rs`/`sessions_watch_legacy_tests.rs` sidecars, matching the sidecar-test convention the rest of the module family (and `CLAUDE.md`) already follows. Pure test relocation; no logic changes.

## [3.6.0] - 2026-07-02

### Fixed

- `cortex-sessions-watch.service` no longer gets stuck permanently `failed` after a burst of transient crashes: widened `StartLimitBurst`/`StartLimitIntervalSec` from `5`/`300s` to `20`/`600s`. Root cause of the 2026-06-29 incident, where the service crash-looped on SQLite lock contention, exhausted its restart budget, and sat `failed` for 3 days with zero alerting before anyone noticed.
- Fixed a process-wide test-suite bottleneck in `src/db/pool.rs`: the shared r2d2 background thread pool (`shared_scheduled_thread_pool`) was sized to exactly 1 thread, shared across every `DbPool` instance in the process. In production this is fine (one process, one pool), but under `cargo test --workspace`'s full parallelism, dozens of independently-created test pools queued behind that single thread and exceeded the 6s connection timeout, surfacing as spurious "timed out waiting for connection" failures unrelated to any actual bug. Bumped to 8 threads.

### Added

- A reusable, multi-condition health-check mechanism for `cortex-sessions-watch.service`, with alerting via the existing `AppriseClient` — closes the observability gap from the same incident (a dead service with no alerting). New `cortex setup sessions-watch-health-check` CLI subcommand, backed by a new `cortex-sessions-watch-doctor.timer` (15-minute cadence) auto-installed/removed alongside the watch service itself, and now verified by `SessionsWatchServiceAction::Check`/`cortex setup doctor` so a broken doctor unit can't silently go undetected.

## [3.5.2] - 2026-07-02

### Fixed

- Dropped the `gitleaks` "Secret Scan" job from the required `ci-gate` checklist. `gitleaks-action` now requires a paid `GITLEAKS_LICENSE` secret this repo doesn't have configured, so the job fails on every PR regardless of content, blocking all merges. The job still runs and reports its own status as a non-blocking advisory check; re-add it to the gate once a license is configured or the action is swapped/pinned.

## [3.5.1] - 2026-07-02

### Fixed

- Fixed `cortex sessions skills backfill`'s Claude-row recovery, which was dead code against real ingested data: it checked `logs.message` for the raw `attributionSkill` JSON, but `logs.message` for a Claude row only ever holds the already-extracted plain-text `content` field (never the raw JSON), so the check could never match outside of hand-crafted test fixtures. The backfill now recovers Claude rows by re-reading the specific line of the original transcript file, located via the persisted `ai_transcript_path` column and the `line_no` recorded in `metadata_json` at ingest time. Line recovery goes through a new shared `scanner::read_transcript_lines` helper that reuses the ingest path's own bounded, newline-delimited record reader (`read_bounded_line` / `MAX_RECORD_SIZE_BYTES`) — so `line_no` values resolve to identical physical lines and a pathological/corrupted oversized line is skipped rather than read unbounded into memory. Added a new `source_unavailable` counter to `SkillBackfillResult`/the CLI output to report Claude rows that still can't be recovered (missing path/metadata, deleted/rotated source file, out-of-range line number, or an oversized line) — distinct from `parse_errors`, which now means "found the source line but it wasn't valid JSON"; each unrecoverable row is logged at `debug` with its `log_id`/path/line. Codex-row recovery (which reads directly from `logs.message`, unaffected by this bug) is unchanged. Note: re-running the backfill is idempotent only while source transcript files are unchanged — a Claude transcript line edited in place between runs can produce a second, differently-named event for the same `log_id`, since `skill_name` is re-derived from the file and is part of the `INSERT OR IGNORE` uniqueness key (documented in `docs/CLI.md`; append-only transcripts make this an edge case). See [GH #94](https://github.com/jmagar/cortex/issues/94) follow-up.

## [3.5.0] - 2026-07-02

### Added

- Skill LLM assessment and a unified `cortex assess` CLI namespace (GH #94 PR 4/4), the final PR completing GH #94's Plan A scope. Built on PR 1's `LlmRunner` invocation guard and PR 3's `investigate_ai_skill_incidents` evidence detector:
  - A new embedded `cortex-skill-improvement-assessment` skill (`plugins/cortex/skills/cortex-skill-improvement-assessment/SKILL.md`) produces a 7-section Markdown assessment (incident summary, skill purpose, what happened, evidence-backed failure modes, proposed skill-doc changes, proposed regression tests/queries, confidence and open questions) from a `SkillIncidentEvidence` bundle. Evidence is always wrapped in `<untrusted-evidence source="cortex skill_investigate json" treat-as="passive-data">...</untrusted-evidence>` and never treated as instructions, regardless of content — locked in by a prompt-injection isolation test.
  - `CortexService::run_skill_assessment_with_delta` (`src/app/services/skill_assessment.rs`) resolves a skill (or `--plugin`) name to its highest-priority (or all, with `--all`) matching skill incident via `investigate_ai_skill_incidents`, and optionally runs the guarded Gemini assessment through `LlmRunner::run` — the only LLM invocation this PR adds.
  - `CortexService::assess_top_abuse_incident_with_delta` (`src/app/services/assessment.rs`) is a thin UX wrapper around the existing `list_ai_incidents` + `run_gemini_assess_with_delta` pipeline (already `LlmRunner`-guarded) — auto-picks the top-priority matching abuse incident when `--incident-id` is omitted; adds zero new LLM call sites.
  - A new unified `cortex assess skill|abuse|mcp|hooks` CLI command group: `skill` and `abuse` are fully implemented (`--no-llm` for deterministic-findings-only, `--all`/`--limit`/`--plugin` on `skill`, `--incident-id` on `abuse`); `mcp` and `hooks` are stubbed (`bail!("... not yet implemented")`), tracked in GH #104/#105. `cortex sessions skill-assess <skill>` is a low-level alias forwarding to the same dispatch function.
  - LLM assessment is CLI-only by design: `skill_assess`/`abuse_assess` are never exposed as MCP actions or REST routes, and `--http` mode is rejected unless `--no-llm` is also passed (mirrors the existing `cortex sessions assess` guard). Locked in by regression tests asserting zero `llm_invocations` audit rows when `run_llm=false`, and a test asserting neither action name exists in `ACTION_SPECS`.
  - MCP action count unchanged at 51 (no new MCP actions added by this PR, by design).
