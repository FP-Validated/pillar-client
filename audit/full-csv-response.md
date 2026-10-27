# Sentry Code audit, full findings list: remediation response

| | |
|---|---|
| Report | Main Review CSV, 100 findings (1 Critical, 6 High, 88 Medium, 4 Low, 1 Info), submitted 2026-10-19 to 2026-10-26 |
| Baseline | `87bbbda` (`public/main`); the earlier H-02 to M-25 branch is carried forward to `17fb6dd` |
| Date | 2026-10-27 |

Findings answered in an earlier response keep that response: H-01, M-15 and M-16 in
[h01-m15-m16-response.md](h01-m15-m16-response.md); H-02 and M-18 to M-21 in
[h02-m18-m21-response.md](h02-m18-m21-response.md); M-22 to M-25 in
[m22-m25-response.md](m22-m25-response.md); M-01 to M-08 and L-01 to L-03 in
[round1-response.md](round1-response.md); M-08 to M-11 in
[round2-response.md](round2-response.md); M-12 to M-14 and L-04 in
[round3-response.md](round3-response.md). M-72 and M-88 were confirmed fixed by code
already on the branch: TON readiness refuses a negative `seqno` and uses checked
subtraction (`round1_ton_confirmation_arithmetic_rejects_negative_head_and_clamps_behind_head`),
and the Aptos source projection keeps no table data (M-12's fix and tests). M-17, marked
resolved in the CSV, was tightened: the packet builder now reserves the wrapper's own
level before checking the message snake
(`packet_message_budget_is_checked_before_building_a_recursive_snake`). The rest are
answered here.

## Critical and High

| Finding | Outcome |
|---|---|
| C-01 attacker-chosen Initia attributes pass the trusted-endpoint check | Fixed. A `move` event is the endpoint's `PacketSent` only when attributes 0 and 1 are `type_tag` (naming the trusted endpoint's V302 token) and `data`. Initia writes those two before the Move event's own fields, so an appended `type_tag` no longer matches. `initia_payload_attributes_cannot_impersonate_the_event_type` |
| H-03 a ULNv2 MPT approval covers the whole block | Fixed by refusal. With an extra-context policy configured, a ULNv2 MPT request is 400 `ULNv2 MPT authorizes an entire block and cannot enforce a per-message policy`; without a policy MPT is unchanged. `message_policy_cannot_authorize_an_entire_mpt_block` |
| H-04 READ depth counted on an unrelated head | Fixed. Each provider's depth vote also reads the canonical block at the pinned height and votes only when its hash equals the pin. `read_confirmation_quorum_cannot_mix_a_pinned_block_with_another_fork` |
| H-05 Canton `from` from an unauthenticated argument | Fixed. A `createArgument.sender` must be in the same event's `signatories`, a `choiceArgument.sender` in its `actingParties`. `canton_policy_sender_requires_same_event_authority_and_bounded_events` |
| H-06 Initia `from` is an address that exists nowhere | Fixed. `/cosmos.crypto.secp256k1.PubKey` derives RIPEMD160(SHA-256(compressed)); `/initia.crypto.v1beta1.ethsecp256k1.PubKey` derives the last 20 bytes of Keccak-256 over the uncompressed key; any other type is refused. `initia_sender_derivation_is_bound_to_the_signer_key_type` |

## Medium

| Finding | Outcome |
|---|---|
| M-26 EVM policy addresses in lowercase | Fixed. `sendLibrary` and `packetEmitAddress` are EIP-55, a `SendUln301` library is lowercase as upstream sends it; the EVM parity replay and the ULNv2 hydration replay now compare exactly |
| M-27 slow bodies hold every connection | Fixed. Signing bodies are read by middleware with a 1 s progress and 3 s total deadline; at most half the connection cap (at most 32) incomplete bodies at a time, the next is 503. `incomplete_upload_budget_preserves_health_connections_and_expires_silent_bodies` |
| M-28 KMS ignores wallet scope | Fixed by refusal. `SIGNER_TYPE=KMS` with `LAYERZERO_WALLETS` or `LAYERZERO_WALLETS_FILE_PATH` fails startup. `kms_mode_refuses_wallet_scope_it_cannot_enforce` |
| M-29 TON signing posts to the bare endpoint | Fixed. The transport normalizes every TON destination JSON-RPC call through the health probe's helper: `/jsonRPC` once, API key as a header, `v3-endpoint` removed. `ton_destination_rpc_normalizes_both_endpoint_spellings_and_credentials` |
| M-30 unreferenced READ markers run quorum rounds | Fixed. Resolved markers and command timestamp markers must match one to one before any RPC. `read_markers_the_command_never_references_are_refused_before_rpc` |
| M-31 Aptos/Movement `from` in short form | Fixed. `0x` plus 64 lowercase hex, `0x0`…`0xf` stay short, and the same value is fingerprinted. `policy_senders_are_canonical_before_provider_quorum` |
| M-32 TRON signing drops the API key | Fixed. All TRON JSON-RPC calls go through `tron_json_rpc_provider_uri_parts`. `tron_signing_strips_auxiliary_credentials_and_promotes_the_primary_key` |
| M-33 bytes32 pathway addresses | Fixed. Sender and receiver are rendered with `address_encoded_by_chain` for their own chain |
| M-34 `onChainEvent.txHash` copied from the request | Fixed. Receipt hash (EVM), ledger version (Aptos/Movement), node `txhash` (Initia) |
| M-35 eighteen serial Sui/IOTA legs | Fixed. Shared objects are fetched in one `multiGetObjects` and function signatures resolved once per observation |
| M-36 failed quorum waits for slow providers | Fixed. After each vote the accumulator checks whether the pending and agreeing voters can still meet the strategy and drops the rest when they cannot. `impossible_quorum_cancels_pending_providers_without_waiting` |
| M-37 prefunded empty Solana account | Fixed. An empty System-owned account is uninitialized; any other account must be owned by the endpoint or ULN program. `solana_optional_accounts_accept_prefunding_but_reject_foreign_owners` |
| M-38 non-EVM policy block zero or false hash | Fixed by refusal. The policy gets block hash and number from agreed evidence; a family that cannot supply a 32-byte hash is refused before the policy call. Canton keeps upstream's empty hash. `policy_identity_uses_evidence_and_refuses_unproven_source_blocks` |
| M-39 deflate sections pin a worker | Fixed. One bounded `Decompress` pass on the decompression pool |
| M-40 Stellar G-account DVN rejected | Fixed. The DVN may be a G-account (account XDR); a receiver must still be a contract. `stellar_account_dvn_uses_account_xdr_without_allowing_account_receivers` |
| M-41 unbounded Solana DVN decode | Fixed. More than 44 characters is 400 before decoding, into a fixed 32-byte buffer. `oversized_solana_dvn_is_rejected_before_provider_work` |
| M-42 one Sui relay crowds out others | Fixed. Payload reads on Sui and IOTA allow at most two in flight per provider entity. `slow_sui_entity_cannot_occupy_the_entire_destination_lane` |
| M-43 receiver view uses unbounded gas | Fixed. Every destination `eth_call` carries `gas: 0xf4240` (1,000,000) |
| M-44 empty gzip members | Fixed. At most 32 members, then 413. `compressed_signing_requests_enforce_a_member_work_budget` |
| M-45 raw header to `bytes32::from_bytes` | Fixed before this round in `c974176` (`keccak256(packetHeader)`), kept |
| M-46 unknown wallet fields ignored | Fixed. `deny_unknown_fields` on wallet definitions. `wallet_scope_typos_fail_before_signer_assembly` |
| M-47 library cell in an unread `extraOptions` ref | Fixed. Only consumed cells must be ordinary and level zero. `ton_packet_ignores_unread_option_refs_but_rejects_exotic_packet_data` |
| M-48 TON `NULL` options rejected | Fixed. `NULL` decodes as empty options; an options failure no longer drops the packet, and a configured policy refuses it. `ton_options_preserve_value_only_and_null_named_requests`, `ton_option_projection_failure_does_not_erase_the_authenticated_packet` |
| M-49 worker library freezes a TON pathway | Fixed. Only the consumed Uln branches are checked. `ton_worker_opaque_library_storage_cannot_poison_receive_configuration` |
| M-50 Canton fingerprint memory | Fixed. 4,096 events, 4 MiB of canonical input, digests streamed |
| M-51 Aptos executor settings from another send | Fixed. Bound to the selected event's raw receiver; two candidates are refused. `aptos_executor_settings_are_bound_to_raw_receiver_and_unique_event` |
| M-52 idle eviction deadlock | Fixed. A connection is idle only after its body is flushed, a writer has 10 s, and every idle connection is considered. `blocked_response_writers_do_not_hide_other_idle_connections` |
| M-53 TON fee options at a different layout | Fixed. Fee fields are read at the contract layout and the class metadata must match. `ton_options_reject_redirected_fee_metadata` |
| M-54 Starknet `from` letter case | Fixed. Parsed as a felt below the field prime, lowercase, same value fingerprinted |
| M-55 Sui GraphQL byte arrays | Fixed. Byte fields stay base64 strings until the trusted event is decoded, under a 16 MiB decoded-byte budget |
| M-56 TON receive value hidden at gas 0 | Fixed. `lzReceive` is emitted when gas or value is nonzero |
| M-57 keys in DNS labels printed | Fixed. Reports show `scheme://<redacted>` for every provider URL |
| M-58 fragmented bodies retain buffers | Fixed. Bodies are copied into one buffer as they arrive. `fragmented_request_releases_each_transport_backing_buffer_before_the_next_chunk` |
| M-59 Aptos bearer to the wrong indexer | Fixed. The indexer URL and its own key are chosen together; another origin gets no RPC headers |
| M-60 IOTA quorum on whole response | Fixed before this round (`type` and `parsedJson` only); the GraphQL path keeps the same projection |
| M-61 Initia sender binds ABCI events | Fixed. The sender vote is the transaction hash and the derived sender |
| M-62 large Stellar ledger record | Fixed. `getLatestLedger`/`getLedgers` responses are streamed into `sequence` and the close time. `projected_http_reads_keep_valid_evidence_when_unread_fields_exceed_four_mib` |
| M-63 TronWeb credentials cross origins | Fixed. TronWeb gets the primary's headers only on the same origin |
| M-64 ordered health collection | Fixed. Chains complete in any order and probes are returned in configuration order |
| M-65 source helper skips `plan_dispatch` | Fixed. Every source quorum loop dispatches through the planner. `source_dispatch_interleaves_entities_before_rpc_admission` |
| M-66 Starknet receipt quorum | Fixed before this round; kept |
| M-67 fake Sui event name | Fixed. Unknown packages are ignored before any decoding. `unrelated_packet_named_events_cannot_poison_a_trusted_sui_send` |
| M-68 unreadable TON sibling voids the trace | Fixed. `malformed_event_opcode_sibling_does_not_erase_a_real_packet` |
| M-69 large MegaETH latest block | Fixed. MESSAGE height comes from `eth_blockNumber` |
| M-70 rejected Canton sibling hides a send | Fixed. Events convert independently. `canton_selection_ignores_rejected_siblings_but_not_selected_packet_errors` |
| M-71 large source transaction blocks policy | Fixed. Sender reads are streamed into the consumed fields |
| M-73 maximum READ request expires | Fixed. Shared headers read once, four in flight. `maximum_read_timestamp_markers_share_headers_and_finish_with_bounded_parallelism` |
| M-74 unrelated Solana options | Fixed. Options are decoded only for the selected packet. `solana_sibling_options_do_not_poison_the_selected_packet` |
| M-75 aborted audit write poisons the session | Fixed. The session is taken out of the slot and returned only after `finish`. `durable-cancelled-begin-reconnect`, `durable-cancelled-record-reconnect` |
| M-76 large Aptos/Movement transaction | Fixed. Streamed projection, 64 MiB wire bound |
| M-77 Aptos fan-out skips interleaving | Fixed. Through the planner. `aptos_source_fan_out_interleaves_entities_before_rpc_admission` |
| M-78 Azure token refresh retries | Fixed. Retries off for the identity client as for Key Vault. `azure_identity_retryable_failures_return_after_one_attempt` |
| M-79 large IOTA event page | Fixed. The page size halves on a size refusal. `iota_event_pages_shrink_without_losing_the_cursor_or_last_event` |
| M-80 Initia index flags | Fixed with M-12; the source projection keeps only `key` and `value` |
| M-81 large MegaETH block | Fixed. Header fields are streamed out of `eth_getBlockBy*` |
| M-82 older Stellar RPC rejects `params` | Fixed. Parameterless calls omit `params` |
| M-83 Initia transaction over 4 MiB | Fixed. Streamed projection of `tx_response` and the signer key |
| M-84 Move reads canonical ULN302 state | Fixed by refusal. A library other than the configured ULN302 is 400 |
| M-85 READ uploads outlive admission | Fixed. READ requests own their connection; an early response or cancellation closes it. `read_upload_socket_closes_on_early_response_and_cancellation` |
| M-86 stalled chain withdraws healthy replicas | Fixed. A round runs at most the background capacity of chains at once, each with a fixed share, so a stalled pool cannot wait out another chain's admission; a never-admitted probe stays unobserved. `stalled_chain_does_not_withdraw_an_observable_healthy_chain`, `health_hundred_chains_complete_in_bounded_parallel_round` |
| M-87 large Initia block | Fixed. Only `header.height` and `header.time` are kept |

## Info

| Finding | Outcome |
|---|---|
| I-01 TON policy principal | Kept as the trace root's `in_msg.destination`, now refused before the policy call when missing or unparseable. `round1_ton_malformed_root_wallet_fails_before_policy_request` |

## Departures from upstream

- H-03, M-28, M-38 and M-84 refuse where upstream signs or proceeds. Each refusal names
  what is missing; none is reachable when the feature it guards is not configured
  (policy, KMS wallet file, a non-default Move library).
- M-26 and M-34 change the policy body to what upstream sends; a policy written against
  the old Pillar body must be updated.
- M-57 removes provider host names from every report.

## Not changed

- The Canton policy body still carries an empty `blockHash`, as upstream does; Canton has
  no blocks.
- Live provider behaviour was not exercised: every scenario runs against recorded or
  synthetic responses.
