// Emits what gasolina-audit 213cd500 produces for one V2-sent bsc->ethereum packet, the
// same inputs as crates/pillar-runtime/src/tests/uln_v2_receive_route_tests.rs:
//   migratedV3: receiver on ReceiveUln301 -> hydrateV1SentEventToV2 + GasolinaEvmSdk.buildULNV3VerifyPayload
//   ulnV2:      receiver on UltraLightNodeV2 -> FeatherProofBuilder.deriveHash + GasolinaEvmSdk.buildULNV2VerifyPayload
// Only the RPC reads are replaced by literals: the event, and the inbound config of a feather receiver
// (proofType 2, utilsVersion 1 - every FPValidator deployment in lz-evm-sdk-v1 3.1.15 that ships source
// sets `utilsVersion = 1`; getFeatherProof throws for 3). No provider is constructed; the methods called
// here never touch it. Deep imports keep canton/stellar/sui SDKs out of the graph.
import { ethers } from 'ethers';

import type { InboundLZUaConfig, LZMessageV1 } from '@offchain-monorepo/common-model';
import { UlnVersion } from '@offchain-monorepo/common-model';
import { getUlnV2ContractAddress } from '@offchain-monorepo/layerzero-core-contracts';
import { FeatherProofBuilder } from '@offchain-monorepo/lz-v1-sdk/src/evm/proof/fp';
import { hydrateV1SentEventToV2 } from '@offchain-monorepo/lz-v2-sdk/src/utils/common/hydrateV1SentEvent';

import { getVId } from '../src/app/hashCallDataBuilder/utils';
import { GasolinaEvmSdk } from '../src/app/sdks/gasolinaSdk/evm';

const ENVIRONMENT = 'mainnet';
const NONCE = 7;
const SRC_EID_V1 = 102; // bsc EndpointV1
const DST_EID_V1 = 101; // ethereum EndpointV1
const SENDER = '0x1111111111111111111111111111111111111111';
const RECEIVER = '0x2222222222222222222222222222222222222222';
const MESSAGE = '0xdeadbeefcafe';
const BLOCK_CONFIRMATION = 12;
const EXPIRATION = 1_751_500_000;
const SRC_TX_HASH = '0x' + '7a'.repeat(32);
const SOURCE_BLOCK = '0x' + 'ab'.repeat(32);

const main = async () => {
    const packetEmitAddress = getUlnV2ContractAddress('bsc', ENVIRONMENT);
    // What the V1 resolver returns for the Pillar fixture receipt (lz-v1-sdk evm/index.ts:517).
    const v1SentEvent = {
        lzMessageId: {
            pathwayId: {
                srcEid: SRC_EID_V1,
                dstEid: DST_EID_V1,
                srcChainName: 'bsc',
                dstChainName: 'ethereum',
                sender: SENDER,
                receiver: RECEIVER,
            },
            nonce: NONCE,
            ulnSendVersion: UlnVersion.V2,
        },
        message: MESSAGE,
        packetEmitAddress,
        onChainEvent: {
            txHash: SRC_TX_HASH,
            blockHash: SOURCE_BLOCK,
            blockNumber: 0x60,
            chainName: 'bsc',
        },
    } as LZMessageV1 & { onChainEvent: unknown };

    const sdk = new GasolinaEvmSdk(ENVIRONMENT, 'ethereum', undefined as never);
    const vId = getVId(undefined, 'ethereum', ENVIRONMENT);

    const hydrated = hydrateV1SentEventToV2(v1SentEvent as never);
    const v3 = await sdk.buildULNV3VerifyPayload(
        hydrated as never,
        BLOCK_CONFIRMATION,
        EXPIRATION,
        vId,
    );

    const inboundConfig = { utilsVersion: 1, proofType: '2' } as InboundLZUaConfig;
    const derivedHash = await new FeatherProofBuilder(undefined as never).deriveHash({
        inboundConfig,
        lzMessage: v1SentEvent,
    });
    const v2 = await sdk.buildULNV2VerifyPayload(
        v1SentEvent,
        derivedHash,
        BLOCK_CONFIRMATION,
        EXPIRATION,
        vId,
    );

    process.stdout.write(
        JSON.stringify(
            {
                _provenance: {
                    upstream: 'gasolina-audit 213cd500 (.changeset/version 1.2.66)',
                    producedBy: 'scripts/gasolina-parity/emit-v2-v3-route.ts',
                    runtime: `node ${process.version}`,
                },
                inputs: {
                    environment: ENVIRONMENT,
                    nonce: NONCE,
                    srcEid: SRC_EID_V1,
                    dstEid: DST_EID_V1,
                    sender: SENDER,
                    receiver: RECEIVER,
                    message: MESSAGE,
                    blockConfirmation: BLOCK_CONFIRMATION,
                    expiration: EXPIRATION,
                    packetEmitAddress,
                    inboundUtilsVersion: inboundConfig.utilsVersion,
                    inboundProofType: inboundConfig.proofType,
                },
                migratedV3: {
                    guid: (hydrated as { guid: string }).guid,
                    hashCallData: v3.hashCallData,
                    details: v3.details,
                },
                ulnV2: {
                    derivedHash,
                    hashCallData: v2.hashCallData,
                    details: v2.details,
                },
                checks: {
                    v3HashIsKeccakOfDvnCallData:
                        ethers.utils.keccak256(v3.details.dvnHashCallData!.dvnCallData) ===
                        v3.hashCallData,
                    v2HashIsKeccakOfDvnCallData:
                        ethers.utils.keccak256(v2.details.dvnHashCallData!.dvnCallData) ===
                        v2.hashCallData,
                },
            },
            null,
            2,
        ) + '\n',
    );
};

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
