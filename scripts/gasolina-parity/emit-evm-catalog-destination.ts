// Stage 1: what gasolina-audit (snapshot 1.2.66) builds for every EVM-shaped destination in its
// available catalog, per environment and per receive version, from one synthetic packet per row.
// Calls upstream's own GasolinaEvmSdk builders and getVId; no provider is constructed (the builders
// never touch it). A builder that throws is recorded as that row's refusal text.
import { UlnVersion } from '@offchain-monorepo/common-model';
import {
    getAvailableChainNames,
    getChainIdForEndpointVersion,
    StaticChainConfigs,
    ChainType,
} from '@offchain-monorepo/static-config';
import { EndpointVersion } from '@layerzerolabs/lz-definitions';

import { getVId } from '../src/app/hashCallDataBuilder/utils';
import { GasolinaEvmSdk } from '../src/app/sdks/gasolinaSdk/evm';

const ENVIRONMENTS = ['mainnet', 'testnet', 'sandbox'];
const SOURCE: Record<string, string> = { mainnet: 'ethereum', testnet: 'sepolia', sandbox: 'ethereum' };
const NONCE = 4242;
const SENDER = '0x0000000000000000000000001111111111111111111111111111111111111111';
const RECEIVER = '0x0000000000000000000000002222222222222222222222222222222222222222';
const GUID = '0x' + '5a'.repeat(32);
const MESSAGE = '0x' + 'c0ffee'.repeat(11);
const BLOCK_CONFIRMATION = 15;
const EXPIRATION = 1_760_000_000;
// Upstream's resolver hands the builder the payload without a 0x prefix (evm_signing_path.json).
const RESOLVED_PAYLOAD = 'ab'.repeat(40);
const V2_HASH_INFO = { lookupHash: '0x' + '6c'.repeat(32), blockData: '0x' + '7d'.repeat(32) };

// Corrected inputs exercise the alternate vId comparisons independently of upstream's folded value.
const CORRECTED_VID: Record<string, Record<string, string>> = {
    testnet: { doma: '10423', lineasep: '10286', scroll: '10214', zksyncsep: '10248' },
};

const eid = (chain: string, env: string, version: EndpointVersion): number | null => {
    try {
        return Number(getChainIdForEndpointVersion(chain, env, version));
    } catch {
        return null;
    }
};

const capture = async (fn: () => Promise<{ hashCallData: string; details: any }>) => {
    try {
        const r = await fn();
        return {
            hashCallData: r.hashCallData,
            targetContract: r.details.dvnCallData.targetContract,
            vid: r.details.dvnCallData.vid,
            ulnCallData: r.details.dvnCallData.ulnCallData,
            dvnCallData: r.details.dvnHashCallData.dvnCallData,
        };
    } catch (error) {
        return { error: String((error as Error)?.message ?? error) };
    }
};

const main = async () => {
    const rows: any[] = [];
    for (const env of ENVIRONMENTS) {
        const src = SOURCE[env];
        const srcV2 = eid(src, env, EndpointVersion.V2)!;
        const srcV1 = eid(src, env, EndpointVersion.V1);
        const chains = getAvailableChainNames(env)
            .filter((c) => [ChainType.EVM, ChainType.TRON].includes(StaticChainConfigs.getChainType(c)))
            .sort();
        for (const chain of chains) {
            const sdk = new GasolinaEvmSdk(env, chain, undefined as never);
            const dstV2 = eid(chain, env, EndpointVersion.V2);
            const dstV1 = eid(chain, env, EndpointVersion.V1);
            let vId: string | null = null;
            let vIdError: string | undefined;
            try {
                vId = getVId(undefined, chain, env);
            } catch (error) {
                vIdError = String((error as Error).message);
            }
            const v3Message = (dstEid: number, sendVersion: UlnVersion) => ({
                lzMessageId: {
                    pathwayId: { srcEid: srcV2, dstEid, sender: SENDER, receiver: RECEIVER, srcChainName: src, dstChainName: chain },
                    nonce: NONCE,
                    ulnSendVersion: sendVersion,
                },
                guid: GUID,
                message: MESSAGE,
            });
            const runFor = async (v: string) => {
                const arms: Record<string, any> = {};
                if (dstV2 !== null) {
                    arms.V302 = await capture(() => sdk.buildULNV3VerifyPayload(v3Message(dstV2, UlnVersion.V302) as never, BLOCK_CONFIRMATION, EXPIRATION, v));
                    arms.ReadV1002 = await capture(() =>
                        sdk.buildULNReadV1VerifyPayload(v3Message(dstV2, UlnVersion.ReadV1002) as never, RESOLVED_PAYLOAD, EXPIRATION, v),
                    );
                }
                if (dstV1 !== null) {
                    arms.V301 = await capture(() => sdk.buildULNV3VerifyPayload(v3Message(dstV1, UlnVersion.V301) as never, BLOCK_CONFIRMATION, EXPIRATION, v));
                    if (srcV1 !== null) {
                        const v1Message = {
                            lzMessageId: {
                                pathwayId: { srcEid: srcV1, dstEid: dstV1, sender: SENDER, receiver: RECEIVER, srcChainName: src, dstChainName: chain },
                                nonce: NONCE,
                                ulnSendVersion: UlnVersion.V2,
                            },
                            message: MESSAGE,
                        };
                        arms.V2 = await capture(() => sdk.buildULNV2VerifyPayload(v1Message as never, V2_HASH_INFO as never, BLOCK_CONFIRMATION, EXPIRATION, v));
                    }
                }
                return arms;
            };
            const row: any = { environment: env, chainName: chain, chainType: StaticChainConfigs.getChainType(chain), srcChainName: src, srcEidV2: srcV2, srcEidV1: srcV1, dstEidV2: dstV2, dstEidV1: dstV1, vId, vIdError };
            row.arms = vId === null ? {} : await runFor(vId);
            const correctedVId = CORRECTED_VID[env]?.[chain];
            if (correctedVId) {
                row.correctedVId = correctedVId;
                row.armsWithCorrectedVId = await runFor(correctedVId);
            }
            rows.push(row);
        }
    }
    process.stdout.write(
        JSON.stringify(
            {
                producedBy: {
                    upstream: 'gasolina-audit snapshot 1.2.66 (manifest sha256 8ad87eb6...; commit 213cd500 label unverified)',
                    entrypoints: [
                        'packages/static-config/src/index.ts:getAvailableChainNames,getChainIdForEndpointVersion,StaticChainConfigs.getChainType',
                        'apps/gasolina/src/app/hashCallDataBuilder/utils.ts:getVId',
                        'apps/gasolina/src/app/sdks/gasolinaSdk/evm/index.ts:buildULNV3VerifyPayload,buildULNReadV1VerifyPayload,buildULNV2VerifyPayload',
                    ],
                    generator: 'scripts/gasolina-parity/emit-evm-catalog-destination.ts',
                },
                input: { source: SOURCE, nonce: NONCE, sender: SENDER, receiver: RECEIVER, guid: GUID, message: MESSAGE, blockConfirmation: BLOCK_CONFIRMATION, expiration: EXPIRATION, resolvedPayload: RESOLVED_PAYLOAD, v2HashInfo: V2_HASH_INFO, correctedVId: CORRECTED_VID },
                rows,
            },
            null,
            1,
        ) + '\n',
    );
};

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
