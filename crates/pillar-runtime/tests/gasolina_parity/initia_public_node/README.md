# Public Initia node LegacyView fixtures

Verbatim request JSON and response body bytes from `rest.initia.xyz` (Initia mainnet), recorded on 2026-10-20 and 2026-10-21 with no credentials. Every call is a read-only `POST /initia/move/v1/accounts/{address}/modules/{module}/view_functions/{function}` against the LayerZero addresses Pillar pins for mainnet: EndpointV2 `0x81d2…e77e`, ULN302 `0x5aab…a012` and LayerZeroViews `0x79cc…2c23`.

LegacyView puts the function's JSON result in a string field `data`: a function with one return value answers the bare value (`002`, `003`, `004`, `007`), a function with several answers an array (`001`, `006`). `003` and `004` ask about a synthetic packet header and verifier, so they show the response shape, not the state of a delivered packet. `005` preserves the unregistered-receiver error. `006` records `get_effective_receive_library` for the registered receiver `0xdd07f825254ed0d753da2b4af4484921c14cf6edd5b6e8fedf81b1bc07ea15de` with source EID 30101: `[ULN302, false]`. `007` records that same receiver's full ULN config. These view captures do not establish a live signing or delivery flow.

| Exchange | Request UTC | HTTP | request.json SHA-256 | response.body SHA-256 |
|---|---|---|---|---|
| 001-mainnet-endpoint-get_default_receive_library_timeout-tuple | 2026-10-20T23:43:51Z | 200 | 7e2526e3e1c7a32f8ff9dc2d0a5730ece40ab02be292e7bac68cc605750488f3 | 1ad876e6aa587f5f1d86bf06ed40f17129635adc355766348eac4a6110a19723 |
| 002-mainnet-endpoint-get_config-uln302-default | 2026-10-20T23:43:52Z | 200 | e939d513bfee5afd3de152f2bd4f22cffb1f5db045aaaced0549da688c0b0d71 | ab405a36601861b51535000e149c6205e1ad618c05c304d41f8e8e292d83fed0 |
| 003-mainnet-views-uln302-verifiable-synthetic | 2026-10-20T23:43:52Z | 200 | cc5c2b07a38498de07fc02d7f2b3a1e5d0021efae2443a1b8c5f86a220fda7c3 | 1c4578e7d5e575f88b0f8196c4c92d462f48138c3abd599aa33fa58413138518 |
| 004-mainnet-msglib-get_verification_confirmations-synthetic | 2026-10-20T23:43:52Z | 200 | d711b2252497c901a59b50e2ff65aec458dae91e76a3d9c67222aab75186b369 | 717543f1760933d182623a987a794efeb27a5ffcdc28d84dddb270d65334b6e9 |
| 005-mainnet-endpoint-get_effective_receive_library-unregistered-500 | 2026-10-20T23:43:52Z | 500 | 836307c34ea52e863c560e749423f0d100375638305a9a9e6454bec50e3d86ab | 5f0404ee6499f663e05902fc3ec2d173a053afcf4b01a53bb1845a5936dd70fe |
| 006-mainnet-endpoint-get_effective_receive_library-registered | 2026-10-21T02:44:00.419631+00:00 | 200 | 2d93bacae6b47b905ffae05a920fe180ccf38be4f2a6149e0d2d89a3ffa16273 | ca70df95142fe0f7c95af25f57ee2ca1a330b36c56a8c573dd512929c40e2c14 |
| 007-mainnet-endpoint-get_config-registered | 2026-10-21T02:50:20.866411+00:00 | 200 | 03ba36250b185f2d0f644af194828b4c62a38fcd292036adec9a43b4d7e53fe4 | 462652302c1ee72df1b3063596ddb587e4edcb687db8aa8e35860b136ba6c99c |
