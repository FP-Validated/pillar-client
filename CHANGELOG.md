# Changelog

All notable changes to this project are documented here. This project follows
semantic versioning for the HTTP surface, the environment-variable contract and
the Prometheus metric names.

## Unreleased

### Security

- `polygon`과 `tron`의 MESSAGE readiness는 요청한 confirmation 수와 finalized head를 함께 확인한다. Receipt 높이의 canonical header number와 hash도 receipt와 같아야 한다. 이 결속은 reference보다 엄격하다. 다른 EVM chain과 `amoy`의 정책은 바꾸지 않는다.
- EVM receipt quorum은 서명에 사용하는 receipt와 log 필드만 정규화한다. `l1Fee` 같은 추가 metadata는 표를 나누지 않는다. Receipt와 log의 transaction/block identity가 다르거나 log index가 중복되면 거부한다. `removed` 생략은 false로 정규화한다. true, null과 잘못된 타입은 거부한다. Transaction hash의 optional `0x` prefix와 대소문자는 같은 값으로 비교한다. Readiness와 ULNv2 MPT 재조회는 resolution의 packet log 내용과 block에 다시 결속된다.
- READ는 DATA를 검증하며 empty call은 같은 URL, headers, EIP-1898 pin의 code를 조회한다. 정확한 0x code만 NoCode이고 0x00/0x6000은 정상 empty return이다. Data/NoCode/ExecutionRevert의 semantic fingerprint는 기존 category/entity quorum을 거친다. NoCode 또는 execution revert의 유일한 quorum만 HTTP 400의 기존 statusCode/body에 code=UNRESOLVABLE_COMMAND, retryable=false를 추가하며 sign stage에 진입하지 않는다. 단일 negative, timeout, transport, malformed DATA와 일반 RPC 오류는 전역 domain refusal이 아니며 양립하는 quorum 둘은 fail closed한다. Numeric revert code 3 또는 numeric -32000과 정확한 execution reverted 메시지의 조합만 분류하며 provided DATA를 검증·정규화한다. Absent/empty revert DATA는 반환 byte가 없다는 동일 의미로 비교한다.
- Extra-context HTTP와 Lambda에 기존 typed `signingContext`를 전달한다. Strict-schema policy consumer는 새 필드를 허용해야 한다. 설정하지 않은 policy와 strict boolean-true gate의 동작은 유지한다.
- Ethereum-style signature 변환은 모든 ECDSA signer에서 recovery ID 2/3을 거부한다. 기존 low-S 정규화 순서와 non-EVM raw recovery ID 형식은 유지한다. KMS 호출 뒤에 거부하므로 cloud signing call 자체를 방지하는 변경은 아니다.
- Sui reads now use the GraphQL RPC surface through each configured `chains.sui.rpc` URI, a deliberate divergence from gasoline's `sui_*`/`suix_*` JSON-RPC forced by fullnode JSON-RPC decommission. Operators must configure GraphQL URLs and preserve distinct providers for quorum; `iotal1` remains on `iota_*` JSON-RPC. The GraphQL adapter maps events, transaction/checkpoint data, object owners, normalized Move function parameters and simulated transaction return values into the existing Sui verdict logic.
- TON 전용 HTTP JSON decoder는 기존 4 MiB 응답 제한과 512-level JSON container nesting 제한을 적용한다. Trace 변환은 transaction hash 중복, 잘못된 topology, 512개 초과 node와 변환 후 512 container 초과 깊이를 조립 전에 거부한다. 서명과 confirmation에 필요한 scalar 필드만 투영한다. Object와 Array를 직접 조립해 subtree 재직렬화를 제거한다. 생략된 leaf children은 빈 배열로 처리한다. 이 정규화는 children 누락을 거부하는 upstream quorum 함수와 의도적으로 다르다. 원본 JSON은 반복형으로 순회하고 해제한다. JSON nesting과 trace node 수는 다른 단위다.

### Audit

- 2026-10-08의 읽기 전용 조회에서 immutable Azure key version의 공개키와 운영 Pillar/Solana DVN config의 64-byte `X||Y` 공개키가 일치했고, config slot `454395711`을 확인했다. 이 항목은 공개키 관측이며, deployed program/source 대응과 live Azure KMS 및 on-chain signature acceptance 조건은 [SECURITY](SECURITY.md#where-responses-still-differ-from-upstream)에 별도로 명시한다.
- TON HTTP 검증은 합성 JSON depth 266과 512를 처리하고 513을 거절했다. Release lifecycle 검증은 topology, quorum 조기 반환과 취소 시 해제를 확인한다. 합성 fixture 결과와 원본 266-depth 응답의 replay 범위는 [AUDIT](AUDIT.md)의 §13에서 구분한다.
- READ HTTP E2E는 정확한 stage/source/destination/status tuple의 Prometheus `_count` 숫자를 읽는다. 같은 series의 중복 관측을 정확하게 계산한다. Test artifact schema 3은 `sign_stage_observation_count`와 tuple별 `stage_observations`로 stage 관측 횟수를 기록한다.
- Gasolina parity README의 재현 절차는 `$PILLAR`와 `$UPSTREAM` 절대 경로로 복사하고 `cargo test`를 `$PILLAR`에서 실행한다. 이전 절차는 upstream checkout 안에서 Pillar 상대 경로를 복사해 실패했다. Canton emitter 절의 미지원 설명은 현재 README/SECURITY 참조와 fixture 증거 범위로 바꿨다. AUDIT §13은 revert code 3에는 message 조건이 없음을 명시한다.

## 2.5.0 - 2026-10-06

### Scope

- Parity target is `gasolina-audit` 1.2.66, identified by its manifest (sha256 `8ad87eb6…`, 2754 files), every supported chain included. Stellar and Canton are in scope; the 2026-10-04 Stellar exclusion is withdrawn.

### Audit

- Add `AUDIT.md`: threat model, trust boundaries, reproduction steps, evidence classes, opt-in PostgreSQL, TLS and Canton E2E instructions, and the inputs this repository cannot supply.
- `AUDIT.md` section 10 records this release's checks: locally 954 passed, 0 failed and 15 ignored before the CI fixes; the 11 opt-in PostgreSQL and 2 opt-in TLS E2Es passed against disposable local servers; the Canton live test did not run, for lack of a ledger and its inputs. The first CI run of the commits that fix the public audit findings below failed on a Rust 1.98.1 clippy lint in `pillar-client`; that fix replaces `chunks_exact(2)` with `as_chunks::<2>()` and leaves behavior unchanged. The second CI run failed because a queued audit readiness probe could dial after its budget had run out; that fix is in the readiness bullet below.
- Add `scripts/build-acceptance-matrix.mjs` and its output under `audit/acceptance/` (1696 rows over the ACTIVE capability table), regenerated from committed inputs only and checked in CI.
- Example provider configurations use reserved `.example` hosts.

### Security

- Return HTTP 400 for a trusted `PacketSent` identity mismatch with the existing `cannot find packet event for srcTxHash ... on pathway ...` envelope, using typed `BadRequest` classification so unrelated provider/internal failures stay 500.
- Bind each EVM source `PacketSent` to the one contract that emits its event interface, with the ULN version taken from that pairing alone: EndpointV2 `PacketSent(bytes,bytes,address)` from EndpointV2 only, versioned by its `sendLibrary` (SendUln302 → V302, ReadLib1002 → ReadV1002); SendUln301 `PacketSent` from SendUln301 only (V301); UltraLightNodeV2 `Packet` from UltraLightNodeV2 only (V2). Previously any of EndpointV2, SendUln302, SendUln301 and UltraLightNodeV2 could emit any of the three topics, and an EndpointV2 event naming a V1-side library took that library's version. Upstream selects the emitter by requested version (`lz-v2-sdk/src/endpoint/evm/index.ts:172-179,668-677`; `lz-v1-sdk/src/evm/index.ts:930-945`). A refused event is skipped like any other non-matching log, so the request ends in the existing 400 `cannot find packet event ...` without signing; correctly emitted events resolve as before. Pillar still does not accept a receive library as an EndpointV2 `sendLibrary`, which upstream's `getUlnVersionFromAddress` would.
- Resolve Aptos ULN301 (`V301`) source sends. Their `0x844bec…::sending::PacketSent` event was rejected by the endpoint-only event matcher, and the V1 endpoint ids they carry (Aptos 108 mainnet, 10108 testnet) mapped to no chain; verified on a recorded mainnet send (version 7469155248) against upstream's own extractor. Each Aptos event type is now bound to its emitter: `channels::PacketSent` from EndpointV2 (V302), `sending::PacketSent` from the Aptos V1 ULN301 module (V301). The same id table names destinations, so an EVM `V301` send to Aptos (destination id 108/10108), refused before for the same unmapped id, now reaches the builder; its call data equals upstream's own builder output on mainnet and testnet (hashCallData, Aptos V1 ULN301 target, vId 108/10108), checked synthetically, not on recorded traffic.
- Validate an EVM `V301` send to Aptos through the production validator instead of refusing it whenever `dvnAddress` was supplied. The already-signed check follows upstream's `getUlnReceiveDetails` → `getDstUlnConfig` → `hasPayloadSigned` (`uln/move/index.ts:137-194`, `uln/aptos/index.ts:270-465`): the receiver's EndpointV1 receive library must be ULN301 `(2, 0)`; the receive config, this DVN's confirmations and the ULN301 view's `verifiable` state are read. `verifiable` returns a `u8`, not a boolean: the deployed `layerzero_view_uln301::uln_301` source emits `0` (VERIFYING), `1` (VERIFIABLE) and `2` (VERIFIED), while upstream's adapter passes `Number(result)` to `mapVerificationState` (`common-model/src/v2/lzMessage.ts:129-148`), which also names `3` and `4` and throws on anything else. Here `2` is signed; `0` is upgraded to signed when the receiver's inbound nonce already covers the packet or the V1 channel stores a payload hash for it, an HTTP 404 meaning none is stored; `1`, `3` and `4` are not signed; any other number, a negative or non-numeric value, a boolean, `null` or a missing element costs that provider its vote. The V1 accounts come from the lockfile-pinned `@layerzerolabs/lz-aptos-sdk-v1@3.0.168` constants. Upstream's own chain, run offline over eleven scenarios on each of mainnet and testnet with EndpointV1 source ids 101/10161 and node-shaped answers (`tests/gasolina_parity/aptos_v301_payload_signed.json`), issues the same reads with the same argument values and reaches the same verdict as `/v2/resolve-and-sign` here; a receive library other than ULN301 is a 400 here, where upstream throws `Unsupported ULN version`. Responses recorded from the public Aptos fullnodes for real V1 receivers (`tests/gasolina_parity/aptos_public_node/`) replay through the same path to the expected verdicts; their `verifiable` and confirmation answers are for a synthetic packet header, so verification-state parity on a delivered network packet is not established.
- Aptos `V301` `verifiable` values that are a boolean, `null`, an empty string or a non-decimal string cost that provider its vote. This is an intentional stricter divergence: upstream's `Number(result)` (`uln/aptos/index.ts:343`) would coerce `true` to `1` and `false`, `null` and `""` to `0` (VERIFYING).
- Read the receiver's EndpointV2 receive library before the receive config on Aptos, Initia and Movement `V302` payload-signed validation, as upstream's `App.validatePayloadSigned` does through `getUlnReceiveVersion` (`app.ts:409-411`, `uln/move/index.ts:137-181`): `endpoint::get_effective_receive_library(receiver padded to 32 bytes, srcEid)` with types `address, u32`. The read was missing. A failed or aborted lookup, for example the Move abort `EUNREGISTERED_OAPP` recorded from the public Aptos fullnode for an unregistered receiver, costs that provider its vote, so a single-provider request is refused before any signature; the returned library address is part of the quorum vote. Refusing an empty or non-address result is stricter than upstream, which throws only on a falsy result and otherwise ignores the address.
- Send Aptos and Movement Move view arguments with the JSON type the fullnode requires: `u8`/`u16`/`u32` as numbers, `u64`/`u128` as decimal strings. Every Aptos and Movement payload-signed read sent its integers as strings, which the public fullnodes reject with HTTP 400 (`expect integer<u8>` / `integer<u32>`, recorded on `api.mainnet.aptoslabs.com`, `api.testnet.aptoslabs.com`, `mainnet.movementnetwork.xyz` and `testnet.movementnetwork.xyz`), so a request with a `dvnAddress` to those destinations could not be validated on either the `V302` `endpoint::get_config` or the `V301` `endpoint_view::get_config` path. Upstream's `AptosMultiProvider` sends the same values BCS-encoded (`multiprovider/src/aptos.ts:337-352`); its requests, captured from the real SDK over a loopback replay at the `getDstUlnConfig`/`hasPayloadSigned` level, carry the same argument values and types as this service's, which is semantic and not byte equality. That capture has no `V302` receive-library read, so the new lookup is checked for order, module and arguments but not against upstream bytes. The `V302` `uln_302::verifiable` state is held to upstream's `0`-`4` range and an empty confirmations result is not a confirmation, as in upstream's `length > 0` check. Aptos and Movement are not in the deployed mainnet roster.
- Resolve Aptos ULN `V2` (LayerZero V1) source sends as upstream does: the transaction at the ledger version `srcTxHash` names, each `packet_event::OutboundEvent` of the V1 LayerZero account decoded (Aptos V1 packet layout, source chain id held to Aptos's EndpointV1 id, `potential attack` otherwise), its block read for the event's block hash and height, and readiness counted from that block by version. The V2 builder hashes a feather proof over the Aptos packet encoding (`bytes32(emitter) ‖ packet`, keccak) and answers any other inbound proof type with upstream's `Unknown proof type`. Upstream's own `getLZSentEventFromSrcTxHash`, `getDerivedHash` and `buildULNV2VerifyPayload` over the packet from its own tests replay here: same reads, event, feather hash and signed hash call data, and the same refusals (`tests/gasolina_parity/aptos_v1_source.json`, 8 scenarios; the transaction wrapper is synthetic). Refuse, with HTTP 400 and before any provider call, an Initia/Movement `V301` source (neither chain has an EndpointV1 id, so no V301 packet can name it).
- Re-read a ULNv2-sent event before rebuilding it for a migrated (V301/V302) receive library, as upstream's `hashCallDataBuilder/ulnV3.ts:54-61` does through `lzSdk.getLZSentEvent`. EVM sources re-read the receipt and take the `RelayerParams` nearest below the matching `Packet` (`defaultAdapterParams(dstEid, proofType)` when the params are `0x`); if those cannot be decoded, the ULNv2 `Packet` logs within half the source's `maxEthGetLogsBlockRange` of the send's block are searched, a reorg having moved it, and the event found there is the one signed for. Aptos sources re-read the transaction and take the adapter params of `executor_v2::ExecutorRequested` or `executor_v1::RequestEvent` for the send's guid, the executor's table default when `0x`. Upstream's outcomes are kept: a send that cannot be refreshed is its 400 `Could not refresh V1 sent event for srcTxHash … on pathway … (possible reorg)`; receipt, log, transaction and resource read failures and Aptos's `invalid adapter params` propagate. The rebuilt event now carries upstream's relayer `options` (`lzReceive.gas` from the adapter params, default `200000`, value `0`, ordered) and `payload` in the extra-context body; neither reaches the DVN hash. The block ranges are generated from upstream's chain metadata (`scripts/generate-chain-metadata-config.mjs`, 335 rows). Upstream's own `LZEvmSdk.getLZSentEvent`, `LZAptosSdk.getLZSentEvent` and `hydrateV1SentEventToV2` over scripted providers replay here, 14 EVM and 10 Aptos scenarios: same reads, order, outcome, gas and hydrated fields (`tests/gasolina_parity/v1_refresh.json`). Reads upstream sends to one provider (log search, default adapter params, Aptos resource and table) use this service's configured quorum.
- Decode EndpointV2-era `PacketSent` options as upstream does (`extractOptionsFromLZSentEvent`, lz-v2-utilities 3.0.168 `Options`): the resolved event, and so the extra-context body, carries upstream's relayer options (`lzReceive` gas/value and read `dataSize`, `ordered`, `nativeDrop` grouped by receiver, `compose` grouped by index) instead of the raw bytes, and an options field upstream cannot decode makes the packet unresolvable, as its swallowed extractor throw does (400 `cannot find packet event`). A ULNv2 `Packet` no longer reports an `options` key, which upstream's V1 event lacks. Upstream's own extractor over 32 vectors replays here (`tests/gasolina_parity/evm_options.json`).
- Resolve Aptos and Movement EndpointV2-era sends as upstream's `EndpointV2AptosSdk.getLZSentEvent` does (`lz-v2-sdk/src/endpoint/aptos/index.ts:182-256`, `decoders/index.ts:56-148`): the requested version picks the event token, every event of it is extracted before any is matched, and a malformed one fails the read with upstream's 500 text (`Both encoded_packet and packet are undefined in the event`, ethers' `invalid BigNumber string` for empty V302 options); the version is `V302` only when `send_library` is present, and the match is upstream's `lzMessageIdMatches` plus the destination chain name, which this service keeps because the signer, expiration check and duplicate query follow the requested name. Options are decoded into relayer options (a V301 `0x` is `{}`), the send library is rendered padded and lowercase, a V301 send names the Aptos V1 ULN301 as its library, and its options gain the executor's adapter params (`executor_v2::ExecutorRequested` first, then `executor_v1::RequestEvent`): gas added, and a type-2 native drop of the destination's address size and non-zero amount put before the event's own drops. An unknown destination eid is upstream's `Invariant failed: Invalid endpointId: <n>`. Replayed against upstream on 36 scenarios (`tests/gasolina_parity/move_source_events.json`); the 8 Movement V301 ones stay refused before any read, deliberately stricter, since Movement has no V301 capability.
- Resolve Sui and IotaL1 sends, which could not resolve before: the endpoint emits `<package>::messaging_channel::PacketSentEvent` (`sui-contracts/src/accountResources.ts:38,55`) and only `…::PacketSent` was accepted. Events now go through upstream's `EndpointV2SuiSdk.getLZSentEvent` path (`lz-v2-sdk/src/endpoint/sui/index.ts:197-257`): exact event type and truthy `parsedJson`, `Packet sent event not found or not valid` when none remains, the Aptos-family extractor with byte fields read as `Uint8Array.from` does, decoded relayer options, and the version from `send_library`. Replayed against upstream on 42 scenarios (`tests/gasolina_parity/sui_source_events.json`), 34 equal; 8 stay stricter: the resolved version must equal the requested one, as the call data is built for the requested version (upstream matches the identity alone), and a packet must be version 1.
- Resolve Starknet sends as upstream's `EndpointV2StarknetSdk.getLZSentEvent` does (`lz-v2-sdk/src/endpoint/starknet/index.ts:180-212`, `starknet/decoders/index.ts:52-120`): events are selected by exact `from_address` and `keys[0]` strings, every one is parsed before any is matched and a malformed one fails the read with starknet.js's `Unexpected end of response`, options are decoded into relayer options (drops to one receiver summed), `sendLibrary` is the felt in decimal as upstream renders it, and an unknown eid is `Invariant failed: Invalid endpointId: <n>`. Replayed against upstream on 21 scenarios (`tests/gasolina_parity/starknet_source_events.json`), 20 equal; a `V301` request for the always-`V302` packet stays refused, since the call data is built for the requested version.
- Resolve Stellar sends, which could not resolve before. The `ContractEvent` reader accepted only event type 0, which is `SYSTEM` (`CONTRACT` is 1), and read the presence flag of an `SCV_MAP`/`SCV_VEC` optional pointer as the item count, so no event the endpoint emits could be decoded; an account `ScAddress` now also reads its `PublicKey` tag. Found by replaying events encoded by `@stellar/stellar-sdk` itself. Resolution then follows upstream's `EndpointV2StellarSdk.getLZSentEvent` (`lz-v2-sdk/src/endpoint/stellar/index.ts:239-275`, `stellar/decoders/index.ts:173-197`): every `packet_sent` event of the endpoint is extracted before any is matched, a missing field fails the read with upstream's `Cannot read properties of undefined (reading 'toString')`, options are decoded into relayer options, a missing `send_library` leaves `sendLibrary` out, and an unknown eid is `Invariant failed: Invalid endpointId: <n>`. Replayed against upstream on 20 scenarios (`tests/gasolina_parity/stellar_source_events.json`), 18 equal; stricter on purpose: a `V301` request for the always-`V302` packet, and a host `SYSTEM` event, which upstream accepts.
- Match Aptos-family `PacketSent` event types as upstream's `getSafeEventToken` does (`common-aptos/src/layerzero-v2/events.ts:46-78`, `common-initia/src/events.ts:40-92`): the first three `::` parts, the account padded, all lowercased, and Aptos `data` truthy. Initia now expects upstream's token `<endpoint>::channels::PacketSent`; it expected `<endpoint>::endpoint_v2::channels::PacketSent`, a form upstream never matches, which Aptos also accepted until now. An Initia `data` attribute that is not JSON fails the read (upstream's text is V8's `JSON.parse` message, not reproduced), and a V301-labelled Initia event takes upstream's update path, failing on `BigInt(txhash)` as it does. Replayed against upstream on 17 Initia scenarios (`tests/gasolina_parity/initia_source_events.json`), 15 equal; a `V301` request stays refused before any read (no Initia V301 capability).
- Sign an EVM-sent ULN V2 packet to an Aptos receiver still on ULN V2 as upstream does (A3, bounded). The EVM ULN V2 `Packet` decoder read every destination address as 20 bytes, so an EVM→Aptos V2 send could not be resolved at all; it now sizes it as upstream's `decodeRawPayloadV2` does (`getAddressSizeInBytes(getChainName(dstChainId))`, 20 when unknown). A V2 send to `aptos` is routed by `endpoint_view::get_receive_msglib` as upstream's `getUlnReceiveDetails` routes it (`(2, 0)` is ULN301, otherwise ULN V2), and with `skipVId` the Aptos builder signs `hashPropose(sha3_256(packet), confirmations, expiration)` for the V1 oracle. Served only on the v2 route, for the two pinned oracles with the packet naming that oracle's EndpointV1 id, a 32-byte receiver and a 20-byte EVM sender; every other `skipVId` request keeps the 400, now also enforced in the builders. Upstream's own routing, feather proof (utils version 2 is the bare packet), vId, builder and signer adapter are replayed through the production HTTP path (`tests/gasolina_parity/aptos_ulnv2_destination.json`): 5 routing rows and 6 payload rows equal, signatures byte for byte. The digest layout agrees with a static decoding of the deployed oracle module; on-chain acceptance is not observed.
- Answer the Solana signer address as upstream 1.2.66 does for a mnemonic, AWS or GCP key: `base58` of the first 32 bytes of the 65-byte SEC1 `04 || X || Y` key (`gasolina-signer-adapter/src/solana/index.ts:9-11`), a bare `X || Y` being given its prefix first; `/signer-info.publicKey` is `X || Y` for every signer kind. This is a response representation only: the DVN verifies the 64-byte `X || Y`, signature bytes are unchanged, and a key of any other shape is refused. An Azure key keeps `base58(X)`, the key registered for the mainnet DVN at offset 17 of `EqkXVEeapm7JqrS1W3AGeN5ZwCRLDUHtr1XY9TuVr4rD` (`EboBSUoo…`), as fixed in `ded0f97`; upstream 1.2.66 has no Azure adapter, so no parity rule applies to it. Both `/signer-info.address` and the signing response's `address` follow this.
- Resolve TON source sends, which could not resolve before. Three defects, all found by replaying a recorded mainnet send (tx `0xec1bd845…`) against upstream's own event: the trace was requested as `{v3}/traces/{hash}`, which toncenter answers with HTTP 500 (now `/events?tx_hash=`, then `/traces?tx_hash=`, then `/transactionTrace?hash=`, as upstream `TonClient3.getTransactionTrace`, for source resolution, block confirmations and extra-context sender alike); class data cells were read one reference too early; and the event topic was compared against the opcode. Acceptance now follows upstream `getLzSentEventFilter`/`isEventValid`: event opcode on the message, `Channel::event::PACKET_SENT` subtopic, sender equal to the Channel address derived from the event's initial storage and owned by the controller, and that Channel's path equal to the packet's.
- Count TON trace quorum votes on upstream's message projection (`tonTransactionTraceMessagesQuorumFn`, `multiprovider/src/ton.ts:40-54`) instead of the whole serialized trace. Each node's inbound message, in pre-order, is reduced to destination, masterchain block seqno, body, bounced, source, hash, event subtopic and opcode topic and folded through `hashFields`. Providers that differ only in fees, state hashes, finality labels or number-vs-string seqno rendering now agree; one that differs in any projected field casts a different vote. A provider whose trace cannot be projected - a body whose BOC checksum fails, a node without `transaction` or `children`, an inbound message without `message_content.body`, or a transaction with no `in_msg` key - casts no vote, as upstream's projection throws there (`common-ton/src/events.ts:111-165`, `common-ton/src/utils.ts:81-93`) and its quorum drops that provider (`common-utils/src/multiFallbackQuorum.ts:243-263`); an explicit `in_msg: null` is skipped, as upstream's `message !== null` does. Every fingerprint or refusal is checked against upstream's own output over the recorded mainnet trace and 20 variants of it (`tests/gasolina_parity/source_replay/ton-trace-quorum.json`). The extra-context TON sender read uses the same projection, as upstream `RpcSdk.getFromAddress` does.
- Add KMS per-lane/resource-string headroom through `PILLAR_KMS_CHAIN_KEY_CONCURRENCY`; the default reduces a single saturated source's maximum occupancy of one resource string from four permits to three with default caps. The limit is process-local and keyed by supplied resource strings, not a physical-key, remote-quota or fleet-wide guarantee; throughput impact is unmeasured. It only acts when a source already holds three concurrent signatures on one key; below that, request results are unchanged.
- Bound shutdown by one grace deadline with an initial endpoint-withdrawal interval, `PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS` (default `min(5s, grace/5)`, carved out of `PILLAR_SHUTDOWN_GRACE_SECONDS`): new signing is rejected and readiness goes 503 from the signal, the listener keeps accepting until the interval ends, draining responses carry `Connection: close`, and remaining connections are cancelled at grace expiry. Nothing changes before the shutdown signal.
- Refuse (500) a resolved `PacketSent` whose destination differs from the requested one before any validation, digest or signature, because the builder follows the resolved destination and the wallets the requested one. The production resolver already requires the two to match, so responses are unchanged.
- Route a `V2`-sent message by its destination receiver's current receive library, as `gasolina-audit` 1.2.66 does (`app.ts:222-342`). The library is read over the requested pathway by exact provider quorum (library address included) before resolution. ReceiveUln301/ULN302 selects the V3 builder over the packet rebuilt with its computed `GUID.generate` guid; every other recognised library (UltraLightNodeV2, V300, ReadLib1002, SimpleMessageLib on sandbox/localnet) keeps the V2 builder. An unknown library is upstream's 500 `Unsupported ULN version: undefined`, a library the endpoint rejects its 500 `Invalid ULN version for lib: <EIP-55 address>`, a provider disagreement a 500, and nothing is resolved, validated, built or signed in those cases. The message-hash check runs first, then readiness, expiration and the already-signed check concurrently, so the first to fail in time answers, as upstream's `Promise.all` does. Previously a migrated receiver got ULNv2 `updateHash` call data targeting UltraLightNodeV2, which ReceiveUln301 cannot accept.
- Stellar destinations sign against upstream 1.2.66's generation-two contracts (ULN302 `CCV4HEII…`/`CCMLPCAW…`, EndpointV2 `CCQLLRE5…`/`CALTBA5S…`), and the already-signed check is upstream's `hasPayloadSigned` over Soroban `simulateTransaction` (receive library, its validity, effective ULN config, confirmations, `verifiable`), quorum-checked. Encodings follow stellar-sdk 16.0.1 (`tests/gasolina_parity/stellar_payload_signed.json`), because upstream's own Stellar bindings are not generated in the snapshot. The rollout gate is removed; a disagreement between the pinned and published ULN302 still refuses per request.
- Canton destinations build and sign ULN302 verifies with upstream's `STATIC_VE3_CONTRACT_ADDRESSES.uln302` and raw-key signer identity (`tests/gasolina_parity/canton_sign.json`); V2 and Read are upstream's `Canton only supports ULN V302`. Canton sources resolve, and Canton readiness and already-signed are checked, through the LayerZero sequencer named by the chain's new `sequencer` provider entry, as upstream does: signed `/scan` and `/vapp` reads verified against the entry's secp256k1 committee (`sequencer-validators`, `sequencer-quorum`), or unverified when it names none. Upstream's own run of that path — provider construction, committee verification, `getLZSentEvent`, `getBlockConfirmations`, `getDstUlnConfig` + `hasPayloadSigned` — replays here exchange for exchange over 55 scenarios (`tests/gasolina_parity/canton_sequencer.json`). The extra-context sender of a Canton source is read as the published `@layerzerolabs/common-canton` 1.2.66 reads it: the JSON Ledger API base is the `rpc` URI without its Canton parameters, each `act-as` party in turn gets a quorum `POST {base}/v2/updates/update-by-id` (wildcard filter, `TRANSACTION_SHAPE_LEDGER_EFFECTS`) with `Authorization: Bearer <token>`, and the first truthy exercise `choiceArgument.sender` or create `createArgument.sender` is the sender, else `''`. The token is upstream's OAuth2 client-credentials grant (`token-url`, `client-id`, `client-secret` or `CANTON_CLIENT_SECRET`, optional `scope`/`audience`; form-encoded; cached in memory until `expires_in - 60` s; one provider per `rpc` entry, built on first use). Without that configuration the read refuses (500) before any request, and it always refuses on `sandbox`/`localnet`, where upstream self-signs an admin JWT. Only a synthetic ledger, identity provider and token test it. A base that keeps a query or fragment, a non-string truthy sender, and a token response without `access_token` are refused where upstream would proceed.
- Canton addresses render as 32-byte hex, as upstream's `getAddressEncodedByChain` does; they were rendered as 20-byte EVM addresses, so no packet to a Canton receiver could match its request.
- A `V2` message to Aptos, Initia or Movement with a vId is upstream's 500 `VId is not supported on aptos yet` instead of a 400 of this service's own.
- The already-signed 400 names the message as upstream does, `JSON.stringify` of the resolved event's `lzMessageId` (`srcEid`, `srcChainName`, `dstEid`, `dstChainName`, then each address in its chain's rendering). It was serde's rendering of the internal pathway: chain names first and padded `bytes32` addresses. Found by the new production differential: for each of the 16 recorded pathways, upstream's own `startServer` in front of its real App and this service's router, both in production `debugMode: false`, answer the signing request and its three refusals (untrusted emitter, already signed, unavailable chain) with equal status and envelope (`tests/gasolina_parity/historical_smoke.json`, `http`).
- A ULNv2 `Packet` no longer carries a synthetic all-zero guid. That guid sent every `V2` request through the guid-keyed EVM already-signed check, which refused any receiver still on UltraLightNodeV2 with `receives on a library this service cannot validate`. Such requests now skip that check, as upstream does for V1 events, and are signed with the V2 builder. No already-signed refusal exists on that path, even with a `dvnAddress`.
- Refuse (400) a ULNv2 feather proof whose destination proof library reports a `getUtilsVersion()` other than 1, before anything is built or signed. Previously any value was signed with the version-1 layout; upstream signs the bare packet for 2 and throws otherwise. Every deployed `FPValidator` with published source reports 1, so responses for those are unchanged. The `inboundProofType` event-extra shortcut, which skipped the on-chain proof-library read and was set only by tests, is removed.
- Durable audit (default off) builds its TLS connector with the ring provider named explicitly. It called `rustls::ClientConfig::builder()`, which panics in this dependency graph (`audit_tls_connector_builds_where_the_process_default_provider_panics`), so a remote audit database could not be reached. Certificates are still verified against WebPKI roots and the DSN host name, and a server that refuses TLS is not retried in plaintext.
- Durable audit sends plaintext only when `host` and every `hostaddr`, which tokio-postgres dials in place of `host`, are literal loopback addresses or a Unix socket. A loopback `host` with a remote `hostaddr` was accepted for plaintext.
- Durable audit readiness uses its own connection. A probe no longer holds or waits for the signing session; the whole probe (waiting, connecting and querying) shares one `PILLAR_AUDIT_TIMEOUT_MS` budget, a probe whose budget runs out while it waits does not dial, and a cancelled or timed-out probe drops its connection. With audit on, each process uses at most two database connections.
- Parse and validation errors no longer echo input. Wallet definitions, the AWS mnemonic secret, `providers-v2.json` and `quorum-strategy.json` report the position and schema-defined field names; unknown keys, entities, categories and unlisted chain or endpoint names are replaced by fixed labels, in startup errors and in refresh logs alike. Which configurations are accepted is unchanged.
- Count TON confirmations from the masterchain block of the `PacketSent` transaction itself, found by exact hash in the provider's trace, and refuse readiness when that transaction is absent. The count started at the trace root, which can be an earlier block and so overstated the depth. Upstream reads the trace root (`packages/sdks/rpc-sdk/src/ton/index.ts:175-187`); this is a deliberate fail-closed divergence.
- `pillar-client` orders EVM signatures by address bytes. String order put checksummed (mixed-case) addresses out of the ascending order EVM verifiers expect. `ReqwestPillarTransport`'s `Debug` output redacts header values; the headers are still sent. The server binary does not depend on `pillar-client`.

### Breaking

- Provider configuration is `providers-v2.json` plus `quorum-strategy.json` only, as in `gasolina-audit` `213cd500`; the `{ uris, quorum }` map is no longer read and a deployment that still supplies it does not start (the error names the retired format). `LOCAL` needs `LAYERZERO_PROVIDER_CONFIG` with `LAYERZERO_QUORUM_STRATEGY_CONFIG`, or `LAYERZERO_PROVIDER_CONFIG_FILE_PATH` with `LAYERZERO_QUORUM_STRATEGY_CONFIG_FILE_PATH`; `S3`/`GCS` read `providers-v2.json` and `quorum-strategy.json` instead of `providers.json`, both on every refresh, and publish the pair as one generation or keep the previous one.
- Provider quorum now counts distinct `(category, entity)` voters against each chain's resolved `rpc` strategy, so two URIs of one entity are one vote. Agreement stays exact and fails closed on ambiguity. Every quorum read - packet resolution, readiness, timestamps, payload-signed checks, receive-library routing, READ block-pinned `eth_call`, extra context, ULN V2 and TON builders - counts votes this way. Reads planned through `plan_dispatch` (readiness, timestamps, payload-signed and receive-library checks, extra context, builders) also refuse up front when healthy providers cannot meet the strategy and fire the smallest entity-interleaved prefix first, then one more provider per 2 s; packet resolution, Move and TON traces and READ `eth_call` still ask every provider at once.
- The startup report prints each chain's strategy and `category/entity` per provider, and flags a chain one entity can satisfy as `single-provider-trust-root`.
- Static LayerZero tables are regenerated from `gasolina-audit` `213cd500` (`.changeset/version` 1.2.66): `lz-definitions` 3.1.2 → 3.1.15 and `lz-ton-sdk-v2` 3.0.167 → 3.0.168, both as pinned by that tree's lockfile. Endpoint ids 853 → 874 and legacy chain ids 915 → 941, all additions; deployment addresses 3911 → 4033 with no removal and 10 changed rows, all testnet `moninet` (still rollout-blocked); environment capability 1221 → 1259 rows with 235 status changes (mostly `ACTIVE` → `DEPRECATED`/`INACTIVE`), none on the mainnet roster this service runs. New EVM chains `alpen`, `anubis`, `hashkey`, `memecore` and `opn` are typed, as is `canton` (`CANTON`); EndpointV1 ids are optional for V2-only chains.
- `LAYERZERO_SUPPORTED_ULN_VERSIONS` is removed; 1.2.66 has no such variable, and a deployment that still sets it is unaffected.
- The signed `vId` stays the EndpointV1 id where one exists, which diverges from `213cd500`: that tree folds EndpointV2 id % 30000 for every chain "by convention", but the deployed LayerZero Labs DVNs on testnet `doma` (`vid()` 10423), `lineasep` (10286) and `zksyncsep` (10248) return the EndpointV1 id (`crates/pillar-runtime/tests/onchain_provenance/dvn_vid.json`; live `eth_call` at `latest`, DVN addresses from LayerZero's metadata API). The divergence covers testnet `doma`, `lineasep`, `scroll` and `zksyncsep` only; `scroll` keeps its EndpointV1 id 10214 as a corrected input, unconfirmed on chain because no public Scroll Sepolia RPC answered (HTTP 403/404/400/521). No mainnet vId differs. `crates/pillar-runtime/tests/gasolina_parity/v_id_by_chain_name.json` is re-emitted from upstream's own `getVId` over the regenerated union and records upstream's values.

Migration, before any deployment of this build:

1. Label every provider URI host with a `category` (`internal`, `dedicated_external`, `shared_external`) and an `entity`.
2. `cargo run -p pillar-config --example provider_config -- convert <current providers JSON> <labels.json> <out-dir>`; it keeps each chain's URIs and headers, turns `quorum: n` into `{ "allOf": [{ "any": n }] }`, and refuses to write a pair that would not start, e.g. a quorum that relied on several URIs of one entity.
3. `... -- validate <out-dir>/providers-v2.json <out-dir>/quorum-strategy.json <LAYERZERO_AVAILABLE_CHAIN_NAMES>` against the roster you deploy.
4. Replace the provider variables (or bucket objects) in the same change that rolls out this image.

### Changed

- Match the upstream TypeScript service's client results on rejected and edge-case requests (`gasolina-audit` 1.2.66):
  - v2 bodies are validated like upstream's Zod schema, in schema order, with Zod 3's messages joined by `, ` (golden: `crates/pillar-api/fixtures/zod_v2_golden.json`); undeclared `pathwayId` fields are dropped; v1 treats `""` and `false` as missing parameters and a `null` envelope body as upstream's TypeError 500.
  - Bodies are read as Express 5.1's `express.json()` (body-parser 2.2.2, iconv-lite 0.7.2) reads them, in its order (golden: `crates/pillar-api/fixtures/http_framework_golden.json`, re-captured on 1.2.66): a missing or non-JSON `Content-Type` leaves `req.body` undefined, so both signing routes are upstream's 500 `Cannot read properties of undefined (reading 'body')`; an empty JSON body is `{}`; a non-UTF charset or an unknown or repeated `Content-Encoding` is a 415, then a declared length over 100 KiB a 413, then an iconv-lite-unknown `utf-*` label a 415; gzip (back-to-back members, trailing zero bytes ignored) and deflate (complete zlib streams only) bodies are inflated under the 100 KiB limit on inflated bytes, and corrupt or truncated streams are a 400; `br` is accepted as a coding but always a 400 here, because no brotli decoder is available (exotic residuals in `SECURITY.md`); UTF-16LE/BE, UTF-32LE/BE, BOM-detected UTF-16/32, UTF-7 and UTF-7-IMAP bodies are decoded as iconv-lite decodes them and a BOM is dropped; a top level other than an object or array is a 400, an unparseable `{ "body": "..." }` envelope a 500; numbers are read and echoed as JavaScript reads and prints them, so `7.0` is accepted as 7. `PillarClient::sign_v1` now sends upstream's `srcUAAddress`/`dstUAAddress` keys.
  - A `V2` request from a source chain that is not EVM, TRON or APTOS is upstream's 500 `Unsupported chain type: <TYPE>` before any RPC.
  - The `srcTxHash` shape gate moved from the HTTP handlers into the core, just before the source read, so upstream's RPC-free errors come first on both routes.
  - An unavailable source or destination chain name, malformed names included, is the 500 `Unsupported dst chain <name>. Available chains : <list> `, source checked first.
  - v1 chain ids are resolved as upstream resolves them: `parseInt` (`0x65`, `101abc`, ` 101` are 101), then the pinned lz-definitions' (3.1.15 since the `213cd500` regeneration) `getNetworkForChainId` over every environment (`1`, a ULN v1 chain id, is `ethereum`), generated into `crates/pillar-config/src/generated_layerzero_legacy_chain_ids.rs`; an unknown id is `Invariant failed: Invalid endpointId: <n>`, a missing or null one Node's `toString` TypeError. v1 nonces take `parseInt(nonce.toString())` (golden: `crates/pillar-runtime/tests/gasolina_parity/legacy_message_id.json`).
  - Packet sender and receiver are matched with `===` against upstream's own `getAddressEncodedByChain` rendering (20-byte lowercase EVM/TRON, base58 Solana, padded lowercase hex for the 32-byte chains), so checksummed, padded, StrKey, TON and bech32 spellings that upstream answers 400 are no longer matched.
  - A version with no builder (`V1`, `V300`, anything the v1 route passes through) is upstream's 400 `Unsupported hash call data builder version: <v>`. `V301`, `V302` and `ReadV1002` are always served.
  - A missing or empty Solana/Stellar `dvnAddress` is a 500 at the build stage, after resolution and validation; TON reports upstream's `parseTonAddress` errors; an empty `dvnAddress` skips the already-signed query.
  - EVM receipts with no trusted PacketSent, reverted EVM transactions, and unmatched Starknet/Stellar packets are the 400 `cannot find packet event ...`; failed Starknet/Stellar transactions are the 500 `Transaction failed for tx <hash>`; a Starknet receipt without a block hash is `Block hash not yet populated for tx <hash>`; a missing, failed or endpoint-less Solana transaction is the 500 `Transaction not found`; Solana, Move, Sui and TON no-match errors use upstream's texts.
  - v1 error bodies stringify the pathway in upstream's legacy key order; v1 addresses are read from upstream's `srcUAAddress`/`dstUAAddress` keys only; `/signer-info` reads `chainName` as Express 5's simple `querystring` parser reads it, so a repeated key is `Chain a,b is not supported`, bracketed keys are other keys (the missing-parameter 400), and an undecodable `%` escape stays literal with U+FFFD for invalid UTF-8.
  The protective differences that remain, and the few framework residuals, are listed in `SECURITY.md`.

### Build

- Pin the CI validation toolchain to Rust 1.98.1 after Rust 1.99 reports
  `double_must_use` in `async_trait` expansion. Keep warnings as errors; runtime
  code and published image tags/digests are unchanged.

### Operator action

- `PILLAR_IMAGE_VERSION` set by a deployment overrides the image's build-time value in `GET /version` and `pillar_build_info`; set it to the deployed tag.
- Before enabling durable audit against a remote PostgreSQL: its certificate must chain to a WebPKI root, since no private CA can be configured, and `max_connections` must allow two connections per replica. Remote TLS was tested only against a local synthetic server.
- Known limitation, present before this release: provider JSON responses are decoded with `serde_json`'s default recursion limit. A toncenter response nested deeper fails to decode, so that provider's read fails; an independent review recorded one testnet `/events` response nested 266 levels deep. It is not known whether LayerZero TON traffic produces such responses.

## 2.4.1-mainnet-20261003.1-phase1 - 2026-10-03

### Security

- Bound source-lane admission and shared actual-target RPC/KMS work with one
  absolute request deadline. Local admission failures no longer count as bad
  provider votes, provider-health failures, or signer backend errors.
- Own finite background health refreshes, preserve quiet-lane queue reservations,
  close resource budgets at drain expiry, and preserve started external signing
  drops as unknown outcomes. The CLI deadline remains connection EOF, not a new
  HTTP timeout response.
- Disable hidden KMS SDK retries, pin mutable key references to resolved immutable
  identities, and make Azure speculative hedges non-waiting and separately counted.
- Add default-disabled PostgreSQL write-ahead signing evidence: validated intent
  and actual transformed input before each effect, signature fingerprints before
  200, retained uncertainty and late evidence, with no replay or permanent nonce
  lock. Real PostgreSQL/production-path crash, concurrency and failure E2Es are
  opt-in; normal workspace tests need no database.
- Keep caller-controlled message hashes out of terminal logs and reduce successful
  GET/HEAD terminal records to debug level.
- Isolate health timeout/admission entries, parallelize refreshes through the
  background lane, and preserve physical foreground headroom across overlapping rounds.
- Acquire KMS admission before reserving audit completion capacity, and reserve
  before arming an attempt. Capacity rejection is admission overload, not a backend
  fault. Workers retain audit identity context.
- Separate audit session-queue timeout from owned database-operation timeout;
  waiting callers cannot invalidate another operation's COMMIT or driver.
- Preserve completed HTTP outcomes across later shutdown; socket deadline rejection
  still records timeout before returning EOF.
- Tie CLI deadline metrics to socket outcomes and bound caller request IDs and
  unconfigured chain/version fields before logging.

### Operator action

- Production deployment keeps audit explicitly off; its database durability,
  capacity and fail-closed acceptance remain separately gated. New limits have
  controlled scenario coverage, not live peak-load calibration.
- OCI `source` names the public `FP-Validated/pillar-client` repository and
  `revision` is the commit the image was built from.

## 2.4.1 - 2026-09-23

### Security

- A `ReadV1002` read is pinned to the block readiness validated. Readiness
  agreed on each time marker's block through a provider quorum, but the payload
  was then fetched by `eth_call` against the block number alone, so a reorg
  between the two phases answered the read - and the signed attestation - from
  a different block at that height, with every honest provider agreeing on the
  new bytes. Readiness now returns the hash it agreed on for every marker,
  including the command's own block-number markers, which it previously checked
  only for depth; `pillar-core` attaches those hashes to the sent event before
  the builder runs, and every READ `eth_call` is issued as EIP-1898
  `{"blockHash": ..., "requireCanonical": true}`. There is no number-tagged
  fallback: a provider whose canonical chain no longer holds the block, or that
  rejects the object form, loses its vote. A marker without a validated hash is
  refused before any RPC, and two readiness reads of one height that disagree
  are refused. Upstream fetches by number
  (`packages/sdks/lz-v2-sdk/src/read/cmdResolver/chain/evm/base.ts:22-28`), so
  this is a deliberate divergence.

  **Operator action:** READ targets need providers, and any proxy in front of
  them, that accept EIP-1898 block parameters with `requireCanonical`;
  `SECURITY.md` gives the probe. MESSAGE pathways are unaffected.

- `AppValidator::validate_readiness` returns `Vec<ReadBlockPin>` (empty for MESSAGE),
  and `LzSentEvent::read_block_pins` carries the validated pins without serialization.

## 2.4.0 - 2026-09-23

### Breaking

- **An external extra-context policy's verdict must now be the JSON boolean
  `true`.** The two transports wrap it differently and the shapes are not
  interchangeable. Over `EXTRA_CONTEXT_REQUEST_URL` the response body itself is
  the verdict, so the body must be `true`. Over `EXTRA_CONTEXT_AWS_LAMBDA_NAME`
  the function must return a JSON object carrying it under `body` -
  `{"body":true}` or `{"statusCode":200,"body":true}` - and a bare `true` is
  refused; that envelope requirement is upstream's (`parsedResponse.body`,
  `apps/gasolina/src/app/app.ts:724`) and is not new. What is new is the type:
  the strings `"true"` and `"false"`, `{}`, `[]`, `{"allow":false}`, numbers and
  `null` are all refusals, on both paths. A Lambda that returns `body` as a
  JSON-encoded string - the common shape - is therefore refused, so confirm the
  returned type and not just the value before rolling this out. On the Lambda
  path an SDK function error, a non-success SDK status code, and a non-success
  `statusCode` inside the payload are refusals as well. The verdict was
  previously generic JSON truthiness, so `{"statusCode":403,"body":"false"}` -
  or any object at all - approved the request. Upstream decides both paths with
  JavaScript truthiness (`app.ts:707`, `:724`), so this is a deliberate
  fail-closed divergence rather than a parity fix. A deployment that sets
  neither variable is unaffected, and that path is still an immediate no-op.

### Security

- The EVM source event is bound to the receipt it was extracted from. The
  resolver now keeps that receipt's block hash, block number, execution status
  and the `PacketSent` log index on the resolved event, and readiness refuses
  when its own later read of the same transaction hash disagrees on any of them,
  or when the transaction is no longer mined. A provider quorum proves the
  providers agreed within one round; it says nothing about whether the two
  rounds observed the same chain state. A reorg that re-included the same
  transaction hash with different logs, or that reverted it, therefore used to
  leave the packet captured in round one being signed while readiness passed on
  the round-two receipt. A receipt whose execution status is not success is now
  refused at resolution, and `status`/`logIndex` are required fields - real
  providers always send both. Non-EVM families carry no such evidence and are
  unchanged. Upstream performs the same two-phase read without binding it.
- The receiver's receive-library check no longer depends on caller input. It ran
  only when the request supplied `dvnAddress`, which is caller-controlled JSON,
  so omitting that field skipped the refusal of an unsupported or invalid
  receive library along with the duplicate-signature query that genuinely needs
  the address. `AppValidator::validate_payload_signed` now takes
  `Option<&str>` and `pillar-core` calls it unconditionally, so on an EVM
  destination the library is resolved and refused whatever the caller sends,
  and only the `hashLookup` duplicate query is conditional on an address.

  The duplicate query itself stays caller-selected, deliberately. It asks "has
  *this* DVN already signed?", which has no subject without an address, and
  this service holds no per-chain DVN *contract* identity of its own to
  substitute - the signer's public-key address is a different thing. Making it
  unconditional would therefore need new configuration and its own review, so
  upstream's gate (`apps/gasolina/src/app/app.ts:494`) is kept: on a chain-native
  destination with no address the check is skipped rather than refused. Supply
  `dvnAddress` if you rely on the payload-already-signed refusal.
- A missing `dvnAddress` on a destination that cannot build without one is now
  a 400 rather than a 500. Solana, Stellar and TON hash the address into what
  they sign, so they fail closed either way, but the combination is chosen by
  the caller and a caller-chosen combination is not a server fault
  (`crates/pillar-layerzero/src/solana.rs`,
  `crates/pillar-layerzero/src/other_non_evm/stellar.rs`,
  `crates/pillar-runtime/src/layerzero_runtime/ton_v3_builder.rs`, and the
  Solana prerequisite in `pillar-core`). The message text is unchanged, so
  existing operator greps still match.
- The maximum connection lifetime is consulted before each read and write
  instead of only when the socket returns `Pending`. A client that kept the
  socket continuously readable renewed the sliding idle window indefinitely and
  never reached the 300s ceiling. `poll_flush` and `poll_shutdown` still
  delegate straight to the socket, so the guarantee is that no application-level
  read or write is serviced after the ceiling, not that every syscall stops.
- `srcChainName` and `dstChainName` are shape-checked at the HTTP boundary to
  1-128 characters of `[0-9a-zA-Z_-]` before anything logs them, and a
  caller-supplied `x-request-id` containing control characters is replaced with
  a generated id. `POST /v2/resolve-and-sign` logged both names with `Display`
  before any validation, and the installed `tracing-subscriber` formatter does
  not escape control characters in ordinary fields, so a name containing a
  newline could forge a log record. All 272 chain names in the generated roster
  satisfy the rule; roster membership is still decided by the core, which
  reports an unknown chain as a caller error.
- Caller-controlled text can no longer forge a log record through an error
  message. Shape-checking the two chain names closed the field that was logged
  directly, but `messageHash` reached the same formatter by a second route: the
  core interpolates it verbatim into the mismatch error (`Message hash
  mismatch, expected: ...`) and `sign_v2` logged that error with `Display`. The
  fix is at the sink - the failure is logged as `?obfuscated`, whose `Debug`
  escapes control characters - so every error path is covered rather than one
  more input. The two `%error` sinks in the CLI accept and connection loops got
  the same treatment. `messageHash` deliberately did **not** get a shape gate
  like `srcTxHash`: that field is spliced into an outbound URL path and so
  needs one, while `messageHash` is only ever compared, and adding a hex gate
  would have introduced a 400 the upstream HTTP surface does not produce.
- Bumped `rustls` to 0.23.45 for RUSTSEC-2026-0285. It arrives only through the
  outbound client stacks - the server speaks plain HTTP - so the practical
  exposure was a peer we dial sending handshake messages in plaintext that
  should have been encrypted, with the transcript still authenticated.
- Bearer credentials no longer reach a derived `Debug`. `RuntimeConfig` held
  both `PILLAR_API_AUTH_TOKENS` and `EXTRA_CONTEXT_REQUEST_AUTH_TOKEN` as plain
  strings behind `#[derive(Debug)]`, and `RuntimeExtraContextConfig` held a copy
  of the latter, so one `{:?}` on a startup or validation error path would have
  written them to the log. Both now write `Debug` by hand and print
  `<redacted>`, keeping presence, token count and the endpoint URL - the
  question an operator actually debugs. Nothing was found printing them today;
  this closes the route rather than a leak. Two tests assert the redaction and
  were proven to fail when only the hand-written `Debug` is reverted.
- The BIP-39 phrase is held in `Zeroizing<String>` in all three types that own
  one - `pillar_config::Mnemonic`, `pillar_signer::LocalMnemonic` and the AWS
  Secrets Manager payload - so it is wiped on drop instead of staying resident
  for the process lifetime behind a long-lived signer adapter. This is a partial
  mitigation and worth stating as one: `serde_json` allocates its own
  intermediate while parsing the wallet JSON, and the process environment block
  that carried it is outside these types' control. `Zeroizing`'s own `Debug` is
  derived and prints the inner value, so the hand-written `Debug` impls remain
  what redacts. A compile-time guard in the signer's redaction test fails to
  build if the field reverts to a plain `String`.

## 2.3.0 - 2026-09-12

### Changed
- Every Solana JSON-RPC read now asks for `maxSupportedTransactionVersion: 1`
  instead of `0`, so transaction v1 (SIMD-0385/0296) is readable. `getTransaction`
  answers `-32015` for any transaction newer than the requested ceiling rather
  than downgrading the response, so the previous `0` would have failed packet
  resolution, readiness and fee-payer observation on every v1 source transaction
  — devnet and testnet already have the feature gate active, and mainnet
  activates it at epoch 1035. The value is one `u8` constant shared by the three
  call sites; it must stay a JSON integer, since a string fails request
  validation with `-32602` on every call, v1 or not. Raising the ceiling is safe
  for providers that cannot serve v1 yet: nodes only compare `version <= max`,
  and a provider that refuses costs one quorum vote instead of corrupting a read.
  Nothing about signing, payload construction or the provider quorum fields
  changes, and v1's new `transactionConfig` deliberately stays out of the
  fee-payer quorum fingerprint so two honest providers cannot disagree over it.

### Added
- `PILLAR_API_AUTH_ENABLED=false` serves every route without a bearer token and
  makes `PILLAR_API_AUTH_TOKENS` optional. The mainnet deployment restricts
  callers with an ingress source-IP allowlist, so a second shared secret bought
  nothing there while still having to be distributed and rotated. Unlike
  `PILLAR_PUBLIC_SIGN_ROUTES` this also opens `/signer-info`,
  `/provider-health/report` and `/metrics`, so it belongs only where such an
  edge restriction exists — a deployment reachable from the internet must leave
  it unset. It takes the exact string `false`, defaults to enabled, and the
  startup report prints `api_auth:` on every boot next to `sign_routes:`.

## 2.2.0 - 2026-09-03

### Added
- `PILLAR_PUBLIC_SIGN_ROUTES=true` serves `POST /` and `POST /v2/resolve-and-sign`
  without a bearer token. LayerZero calls a registered DVN endpoint with no
  credential of ours, so a deployment meant to receive that traffic could not
  demand one and answered every call with 401. The switch is opt-in, takes the
  exact string `true`, and is scoped to those two routes: `/signer-info`,
  `/provider-health/report` and `/metrics` stay authenticated in every mode, and
  `PILLAR_API_AUTH_TOKENS` stays required, so forgetting to configure tokens
  still fails the boot rather than silently opening the service. The startup
  report prints `sign_routes:` on every boot so the posture cannot change
  unobserved.

### Fixed
- `pillar_sign_stage_duration_seconds` now records. The production composition
  injected `NoopSignStageObserver`, so the family rendered its `HELP` and `TYPE`
  lines with no samples beneath them — indistinguishable, to an operator, from a
  service that had signed nothing. `PillarMetricsStageObserver` existed but was
  never constructed anywhere outside unit tests, which is why no test caught it:
  they exercised the observer directly rather than the assembler. A test now
  drives the real assembler and reads the registry the HTTP surface serves.
- A malformed protocol field is a 400, not a 500. `ulnSendVersion` and the
  pathway extras deserialise as `serde_json::Value`, and the HTTP boundary
  checked presence only, so a non-string version reached the core, which could
  only classify it as an internal fault. The boundary now type-checks the
  protocol fields against the closed version set, matching where upstream puts
  its Zod schema, and the core reports caller input as `BadRequest` on both the
  v1 and v2 routes — v1 copies its `ulnVersion` straight through.
- `pillar_provider_request_errors_total` covers every quorum path. The Move and
  TON resolvers built their own accumulators and called `finish` directly, so
  those chain families could fail quorum on every provider while the counter an
  operator alerts on stayed at zero. All three paths now end in one
  `finish_quorum` helper. The metric's `HELP` text no longer claims to count
  provider failures generally; validation-stage provider failures surface as
  `pillar_sign_stage_duration_seconds{status="error"}` instead, which is now
  a real signal rather than an empty family.

### Changed
- `SECURITY.md` and the builder-selection comment in `pillar-core` now cite the
  upstream call chain rather than asserting parity, and identify the exact tree
  they were read from by the `chainNames/*.ts` content hashes already recorded in
  the generated environment table's provenance header. Two independent reviews
  reported that upstream runs an entity/category provider trust model and a
  V2-to-V3 receive-library builder override. Neither is on the runtime path in
  that tree, and the dormant scaffolding that prompted both readings is now named
  explicitly along with the reason it is dormant. One review's source was a
  differently-rooted archive that has not been obtained, so its claims are
  recorded as not reproducing against the identified tree rather than as
  refuted — a distinction worth keeping, since only one of those two statements
  is something this workspace can establish.

- The server no longer speaks HTTP/2. It was serving h2 prior-knowledge
  connections, which nothing here asked for: `hyper`'s `http2` feature is
  enabled process-wide by `aws-smithy-http-client` and `tonic` for the KMS and
  storage clients, and the `hyper-util` `auto` builder then negotiated it. The
  accept loop holds one semaphore permit per connection, so a single h2
  connection multiplexed up to 200 concurrent streams - the SETTINGS frame
  advertised `MAX_CONCURRENT_STREAMS=200` - behind one permit, and
  `PILLAR_MAX_CONNECTIONS` bounded sockets rather than work. Connections are now
  served by `hyper::server::conn::http1`, and a test writes the h2 preface and
  fails if it is answered. The `server-auto` feature is also dropped, but that
  alone would not prevent a regression: `hyper_util::server::conn::auto` is
  gated on `any(http1, http2)`, both of which the reqwest client stack enables,
  so the module stays compiled regardless of what this workspace declares.
  `auto::Builder::http1_only()` could not express this: hyper-util documents it
  as a no-op under `serve_connection_with_upgrades`.

### Changed
- The payload-already-signed check now asks the destination endpoint which
  receive library the receiver OApp actually uses, instead of deriving it from
  `dstEid`. Deriving it reads the wrong contract for an OApp on a non-default
  receive library, so a message already attested there looks unsigned. A receive
  library that is not one of `ReceiveUln302`, `ReceiveUln301` or `ReadLib1002`,
  or a non-default one the endpoint itself rejects, is now refused rather than
  guessed at. The resolution runs per provider and the quorum agrees on the
  library, not only on the verdict.

  On the exploitability of the old behaviour: a second signature was **not**
  reachable in practice, because the same code path was blocked earlier by the
  address-width defect below - the check never dialled at all and failed
  closed. Verified by running the pre-fix image against the same request: it
  answered `Payload-signed validation unavailable` with zero `eth_call`s. The
  derivation was still wrong, and fixing the width alone would have made the
  second signature reachable.
- The generated EVM deployment table now also carries the V1 `Endpoint`
  address, needed for pathways whose destination endpoint id is a V1 one.
  Pre-existing rows are unchanged.

### Fixed
- `pillar_provider_config_age_seconds` no longer reports a frozen configuration
  as fresh. The gauge was written from inside the refresh loop, and its accepting
  branch wrote `0`, so a loop that died right after a success left the metric
  pinned at zero for the life of the process - the one value meaning "nothing is
  stale". Both this age and the new heartbeats are now computed when `/metrics`
  is scraped, from a timestamp their owner stamps, so a loop that stopped for any
  reason reads as growing. It also means a scrape taken before the first refresh
  interval carries a sample at all; previously the metric was absent for the
  first sixty seconds of every process.
- The provider-rank and provider-health-cache loops are now aborted when the
  runtime app is dropped. Dropping a tokio `JoinHandle` detaches the task rather
  than stopping it, so the previous `_provider_rank_refresh` field controlled
  nothing and both loops kept issuing provider RPC after the server stopped
  serving. `RemoteProviderConfigOwner` already did this for the config loop;
  this is the same contract for the other two. They are also spawned after every
  fallible initialisation step, because `Drop` cannot run on a value that was
  never constructed: a failure in `StartupReport::from_parts` used to return past
  two live loops and leave them detached with no owner able to stop them.

### Added
- `pillar_background_task_heartbeat_age_seconds{task}` — one sample per
  background loop (`provider_config_refresh`, `provider_rank_refresh`,
  `provider_health_cache_refresh`). Nothing awaited these tasks' handles, so a
  loop that panicked or wedged left no trace on any surface; a panic reached
  stderr through the default panic hook only, bypassing the `tracing` pipeline,
  and no metric moved. Alert above roughly three times the interval. **Add this
  to dashboards and alerts in the same rollout**, alongside the age metric that
  can now actually fire.

  It reports *that* a loop stopped, never *why*: a panic, a hung RPC and a task
  that never started all read as a growing age, deliberately, because the
  operator's next step is the same for all three. A loop that runs and fails is a
  different fact with its own metrics - the heartbeat stays healthy while
  `pillar_provider_config_refresh_total{result}` carries the failure.

### Fixed
- The EVM payload-already-signed check now works on a real packet at all. A V3
  pathway names the receiver as `bytes32`, and every `address` argument the
  check encodes rejected anything but 20 bytes, so the first call failed with
  `invalid address length: 32`. That error was swallowed into "validation
  unavailable", which fails closed - no wrong signature was ever issued - but
  the check itself had never run. EVM `address` arguments are now narrowed from
  the pathway value at the lookup input, and refused when the padding is not
  zero. The packet header keeps the padded form, so what gets signed is
  unchanged.

- **The signing path now follows an accepted provider-configuration refresh.**
  Every request-time consumer - the packet resolver, the read payload resolver,
  the TON and ULN V2 builders, the validator - held a provider map cloned at
  startup, so a refresh moved `/provider-health` and left signing dispatching
  to the endpoints the process booted with, with nothing reporting that the two
  disagreed. All of them now read one shared generation. An operator who
  rotates an RPC endpoint no longer has to restart for signing to use it.
- `GET /available-chains` and the signing gate now read the same object - the
  generation now serving - instead of each holding a roster copied at startup.
  The advertised set is unchanged in practice, because the chain set is fixed
  for the process lifetime; what this removes is a second copy that could drift
  from the configuration actually in use.
- A refresh may not add a chain. Signing capability - wallets, signer backends,
  chain types, contract tables, builders - is assembled once at startup, so a
  chain appearing in a later remote write is dropped from the configuration
  rather than advertised as something this process could sign for. This is a
  deliberate divergence from upstream, which builds its chain SDKs per request
  and can therefore serve a chain that appears in a later write. Adding a chain
  here requires a restart.
- **Provider ranking now actually applies.** The health report publishes a
  redacted URL - it is a public payload and an RPC key lives in the path or
  query - and rank was being keyed off that redacted string, while dispatch
  looks providers up by the URL it dials. For every provider carrying its
  credential in the path or query, which is every realistic one, the two never
  matched: an unhealthy provider was never excluded and latency ordering never
  applied. Two URLs on one host also collapsed to the same redacted key. The
  entry now carries the dialled URL in a never-serialized field and ranking
  keys off that; the published payload is byte-for-byte unchanged.
  Tron needed a second half of the same fix. Its probe deliberately dials a
  different URL from the configured one - userinfo moves into an
  `Authorization` header and the `tron-api-key`/`tron-web-url` parameters are
  stripped - while Tron reaches the signing path as an EVM-shaped chain and
  dispatches on the configured URI verbatim, so ranking has to be keyed by the
  latter. It now is. Every other family's primary probe already dials what
  dispatch dials.
- Provider rank is not seeded from a health probe that straddled a refresh. Rank
  is keyed by `(chain, url)` with headers stripped, so an operator rotating
  credentials on an endpoint would otherwise have the failures observed under
  the old ones recorded against the fixed one, and dispatch would keep excluding
  it until the entry aged out - failing requests closed for a chain whose quorum
  could then not be met, minutes after the configuration was fixed. Such
  observations are discarded; the endpoints stay unranked, which dispatch reads
  as the normal pre-ranking default.
- The signing gate refuses a chain that is no longer served, naming what is
  served now. `PillarApp` held the roster it was constructed with, so a chain
  removed by a refresh was admitted and then failed deeper with an error about
  provider configuration instead of about the chain.
- `GET /ready` decides from one generation. It reads provider state twice - the
  health snapshot, then the chain roster - so a refresh landing between them
  could report on a combination of one generation's health and another's chain
  set that never served.
- One sign request now reads exactly one provider generation. Previously each
  consumer read the shared map when it happened to need it, so a refresh
  landing mid-request could have the event resolved against one provider set
  and the payload-already-signed check run against another.
- The provider-health cache is now keyed by configuration generation. It serves
  a value for up to two minutes, and `/provider-health` and `/ready` are
  computed from it, so a refresh inside that window could previously report on
  endpoints that were no longer configured. A refresh now expires it.

  The generation is read *before* each probe, not after. A refresh can be
  published while a probe is in flight, and that probe already read the
  endpoints of the generation it started under, so labelling it with whatever
  is serving when it returns would present an observation of the replaced
  provider set as describing the new one - and then serve it for the whole
  TTL. The same rule covers a probe that fails mid-refresh, which is retried
  against the configuration now serving rather than falling back to the value
  from before the replacement, and the startup seed, which is labelled with the
  generation the composition root probed rather than the one live when it hands
  the report over. If the configuration is replaced under every attempt, the
  cache reports failure rather than answering with an observation of a
  configuration that is not serving.

- The four provider-backed validations of a sign request - message hash,
  readiness, expiration and payload-already-signed - now run concurrently
  instead of one after another, matching upstream's `Promise.all`
  (`apps/gasolina/src/app/app.ts:495-510`). A valid request waited for the sum
  of those round trips and now waits for the longest. Extra-context validation
  still runs only after the others pass, and the errors are still reported in
  the previous order, so which error a caller sees is unchanged; an invalid
  request now issues the later checks before failing, which is the same trade
  upstream makes.

### Documented

- `SECURITY.md` now states what a provider quorum proves. A quorum of N is N
  URIs returning the same value; the configuration has no notion of who
  operates an endpoint, so two URIs from one provider satisfy a quorum of 2
  while sharing one failure domain. Upstream's consumed provider entry is the
  same shape, so this is a property of the trust model to arrange operationally,
  not a regression against upstream.
- Recorded that on EVM the destination receive ULN version is derived from the
  endpoint id rather than read from the receiver's actual receive library as
  upstream does, that the two agree for receivers on the default library, and
  that for a receiver with a non-default library the payload-already-signed
  check can miss an existing verification and permit a second signature.
- Recorded that the generated LayerZero tables are pinned snapshots with no
  automated upstream comparison, and why public CI cannot perform one.
- `provider_validation` now says in the module documentation that no runtime
  path calls it, and that the same split exists upstream, so its presence is not
  read as an entity-aware quorum the signing path enforces.

### Security

- A remote provider-configuration refresh is now admitted by the same gate as
  startup. `StaticProviderConfig::new` only restricts the map to the requested
  chains, so a snapshot with no URIs or a zero quorum loaded happily and
  replaced the active one every 60 seconds. That map is what
  `/provider-health` and `/ready` are computed from, so the readiness false
  positive closed at startup could come back from S3 or GCS. A rejected
  snapshot leaves the previous one serving and counts under
  `pillar_provider_config_refresh_total{result="rejected"}`, distinct from
  `error` for a failed fetch. Signing was not affected: request-time
  validation reads the configuration captured at startup, not this map.
- The refresh loop now records into the registry `/metrics` renders. It built
  its own `PillarMetrics`, so `pillar_provider_config_refresh_total` and
  `pillar_provider_config_age_seconds` were never served and a bucket that
  had been failing for hours was invisible to alerting. The counter claim in
  the entry above was true of the code and false of the endpoint until this
  change; an end-to-end test now drives the real loop and asserts all three
  outcomes appear on the app's rendered `/metrics`.
- `pillar_provider_config_age_seconds` is measured from the last accepted
  snapshot. It was measured from process start, so a run that refreshed
  cleanly for ten minutes and then failed once reported ten and a half
  minutes of staleness instead of thirty seconds. A rejected snapshot is not
  a success and does not reset it.

- Bumped `h2` to 0.4.19 for RUSTSEC-2026-0258 (unbounded empty DATA frames).
  This is reachable from ingress, not only from outbound clients: the server
  negotiates h2c, so the advisory applied to the signing endpoints themselves.
- Resolved RUSTSEC-2026-0253 instead of ignoring it. `aws-sdk-s3` 1.144.0 is
  the first release to accept `lru` 0.18.2, so the advisory is now fixable;
  `aws-config` 1.11.0 and the sibling AWS SDK crates moved with it to keep a
  single `aws-smithy-schema` generation in the graph. The `.cargo/audit.toml`
  ignore entry is gone and `cargo audit` passes with no suppressions. The
  manifest floors were raised to the resolved versions, so a fresh dependency
  resolution cannot select a version that requires the vulnerable `lru`.

  Operators should smoke-test against staging before rolling this out: the AWS
  SDK clients for KMS, S3, Lambda and Secrets Manager all moved, and the unit
  tests exercise them through fakes rather than live endpoints.
- Documented the Stellar deployment-address caveat in
  [SECURITY.md](SECURITY.md#known-caveats). Every pinned Stellar address —
  including the trusted endpoint address used for source-event filtering —
  disagrees with LayerZero's live deployment metadata on both `mainnet` and
  `testnet`. Starknet, pinned from the same generation, agrees on all
  equivalent values. Confirm on-chain before enabling Stellar. No addresses
  were changed; this is a disclosure, not a fix.
- **`HEAD` no longer bypasses authentication.** axum dispatches `HEAD` to the
  registered `GET` handler, and the credential check matched on the raw method
  string, so `HEAD /metrics` ran the handler and returned 200 while
  `GET /metrics` returned 401. The body was stripped but `Content-Length` was
  set from the real body first, so the size leaked, and the handler's side
  effects still ran — `HEAD /provider-health/report` probed every provider of
  every chain, bypassing the 15s cache. `HEAD` now inherits the `GET` route's
  requirement.
- Fixed a truncation in the constant-time token comparison: the length
  mismatch was folded in as `(a ^ b) as u8`, so a difference that is an exact
  multiple of 256 became zero and the byte loop then compared the absent bytes
  against an implicit zero. Header parsing rejects NUL bytes, so this was not
  reachable over HTTP; the comparator no longer depends on that.
- Added deny-path coverage for authentication. Every `(method, path)` in the
  authenticated set is now asserted to return 401 with no credential, a wrong
  token, a non-`Bearer` scheme and a token prefix — `HEAD` included. There was
  previously no test for a rejection at all, which is how the `HEAD` gap
  survived.

### Changed

- Startup now refuses a provider configuration that request time would reject
  anyway: a selected chain with no provider URI, `quorum` of 0, or `quorum`
  greater than the number of configured URIs. It also refuses to start when
  `LAYERZERO_AVAILABLE_CHAIN_NAMES` selects nothing present in the provider
  configuration. Previously such a chain reported `GET /ready` as `READY` and
  `GET /provider-health` as healthy while every sign request for it failed with
  `No provider URI for chain ...`. The readiness snapshot's treatment of an
  empty provider list as healthy is upstream behaviour and is unchanged; the
  configuration that makes it observable is now rejected. The gate reuses
  `required_provider_quorum`, so it cannot drift from the request-time check.
- Startup now names entries that were silently dropped. Upstream matches
  `LAYERZERO_AVAILABLE_CHAIN_NAMES` verbatim with no trimming, so
  `ethereum, bsc` loses ` bsc`; that parsing is unchanged for parity, but the
  dropped entries are logged. Likewise `LAYERZERO_SUPPORTED_ULN_VERSIONS`
  entries other than `V2` and `V301` have no effect — the variable gates only
  those two builders — and are now logged instead of being ignored in silence.

### Documentation

- Added `CONTRIBUTING.md`, covering the fail-closed rule, the upstream-citation
  requirement for protocol and address claims, the prohibition on hand-editing
  generated tables, and the fixture-naming rule that recorded values must not
  be presented as upstream-reproduced.
- Corrected four README claims. Not every response is enveloped: `GET /`
  returns a bare `HEALTHY` and `GET /metrics` returns Prometheus text. Stellar
  is described as rollout-blocked on both environments rather than "confirm
  before enabling", because listing it in `LAYERZERO_AVAILABLE_CHAIN_NAMES`
  does not enable it. The destination-family table is labelled a builder
  capability matrix, since a builder existing implies neither a deployment
  entry nor an operationally enabled chain. And `ULN V2` is distinguished from
  `Endpoint V2`, which both read as "V2" but are different axes.
- Documented that readiness is service-level — ready while at least one
  configured chain is healthy — and that both readiness and provider health are
  served from a cache that is fresh for 15s and can serve a stale value for up
  to 120s when a refresh fails. Also documented that a Kubernetes readiness
  probe belongs on `/ready`, not `/`, which is a constant liveness string.
- Recorded the remaining known gaps in `SECURITY.md`: the TON DVN verify
  fixtures are recorded rather than reproduced from the upstream
  implementation, `movement` currently resolves to the same Move addresses as
  `aptos` and will keep doing so until the tables are regenerated, and ULN
  `ReadV1002` is EVM-only.

### Internal

- The provider-config refresh decision and its write live in one function,
  `apply_refreshed_snapshot`, so the active map cannot be replaced on a path
  that skipped validation. Three tests drive it with a candidate carrying no
  URIs, a zero quorum and a quorum above the URI count, and assert through
  `RemoteProviderConfigOwner::snapshot()` that the previous configuration is
  still the one serving - the loop's own sixty-second sleep and live bucket
  read stay out of the test. Moving the write above the check fails them.
- Renamed the TON vector tests to describe what they assert
  (`*_matches_recorded_vector`, `boc_round_trip_is_byte_identical`,
  `repr_hash_matches_recorded_execute_params_cell`); the constants and
  assertions are unchanged.
- Restricted the CI workflow's `GITHUB_TOKEN` to `contents: read`.
- The runtime image now records the commit it was built from. `Dockerfile`
  accepts a `VCS_REVISION` build argument and writes the OCI
  `org.opencontainers.image.*` labels; CI passes the commit SHA and then asserts
  the label matches it. Previously a pulled image carried no link to its source:
  `PILLAR_IMAGE_VERSION` fell back to `unknown` whenever the builder omitted the
  argument, and a tag can be moved after the fact. Operators verifying a rollout
  can now read the revision off the image itself rather than trusting the tag.
- Vulnerability reports now go through GitHub private vulnerability reporting
  instead of an email address.
- Every crate declares `publish = false` and inherits `repository` from the
  workspace, so the workspace cannot be pushed to crates.io by accident and the
  generated SBOM carries the repository URL.

## 2.1.0

### Breaking

- **Environment variable renamed**: `GASOLINA_IMAGE_VERSION` is now
  `PILLAR_IMAGE_VERSION`. There is no fallback; the old name is ignored.
- **Prometheus families renamed**: `gasolina_http_requests_total`,
  `gasolina_http_request_duration_seconds`, `gasolina_build_info` and
  `gasolina_sign_stage_duration_seconds` are now the `pillar_*` equivalents.
  Label sets and bucket boundaries are unchanged. Dashboards, recording rules
  and alerts must be updated in the same rollout.
- **Authentication is now required.** `POST /`, `POST /v2/resolve-and-sign`,
  `GET /signer-info`, `GET /provider-health/report` and `GET /metrics` require
  `Authorization: Bearer <token>` matching one of `PILLAR_API_AUTH_TOKENS`.
  The service refuses to start if that variable is missing or holds a token
  shorter than 32 characters. Prometheus scrape jobs need the token configured.
- **Container health check target changed** from `GET /` to `GET /ready`.
  `GET /` remains a constant liveness string; `GET /ready` reflects signer and
  provider state and turns 503 as soon as shutdown is signalled.

### Added

- `GET /ready` readiness endpoint (200 `READY` / 503 `NOT_READY`).
- Graceful shutdown on SIGTERM/SIGINT: the listener stops accepting, readiness
  flips to 503, in-flight requests drain for up to
  `PILLAR_SHUTDOWN_GRACE_SECONDS` (default 25), then the process exits 0.
- Connection admission cap via `PILLAR_MAX_CONNECTIONS` (default 1024).
- Metrics for operator alerting: `pillar_provider_config_refresh_total{result}`,
  `pillar_provider_config_age_seconds`, `pillar_signer_errors_total{backend}`,
  `pillar_provider_request_errors_total{chain,kind}`.
- Starknet and Stellar destinations now work on `testnet` as well as `mainnet`;
  the destination ULN address is resolved per environment and the testnet
  Stellar endpoint id (40600) was added.
- `stellar_contract_id_from_strkey` derives Soroban contract ids from strkeys
  (base32 + CRC16-XModem), replacing a hardcoded byte constant.
- Root `LICENSE`, `README.md`, `SECURITY.md` and this changelog; per-crate
  package descriptions; declared MSRV; `overflow-checks` enabled in release.

### Changed

- The HTTP method metric label is normalised to a fixed allowlist, so unknown
  request methods can no longer create unbounded Prometheus series.
- Remote provider-configuration refresh failures are now logged at `error` and
  counted; the configuration age gauge keeps climbing while refreshes fail.
- Error responses redact cloud key identifiers (AWS ARNs, GCP key-ring resource
  names) in addition to URLs.
- `skipVId` is now rejected on the legacy `POST /` path as well as on
  `POST /v2/resolve-and-sign`.
- The startup report shows the effective quorum per chain and flags chains whose
  quorum is 1 as a single-provider trust root.
- Generated LayerZero and TON configuration headers carry only publishable
  provenance (upstream package, version, input hashes, entry counts).

### Removed

- Operator-specific deployment tooling (`scripts/deploy-pillar-testnet.sh`,
  `scripts/post-rollout-smoke.mjs`). Deployment is owned outside this
  repository.
- The CLI has no subcommands; the binary only serves HTTP.

### Migration from the previous naming

1. Set `PILLAR_IMAGE_VERSION` wherever `GASOLINA_IMAGE_VERSION` was set.
2. Generate a token (≥32 characters), set `PILLAR_API_AUTH_TOKENS`, and add the
   bearer header to every caller and to the Prometheus scrape job.
3. Point liveness at `GET /` and readiness at `GET /ready`.
4. Rename `gasolina_*` to `pillar_*` in dashboards, recording rules and alerts.
5. Set an explicit `quorum` ≥ 2 per chain in the provider configuration.
