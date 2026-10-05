import { UlnVersion } from '@offchain-monorepo/common-model';
import { getChainIdForEndpointVersion, getAvailableChainNames, StaticChainConfigs, ChainType } from '@offchain-monorepo/static-config';
import { EndpointVersion } from '@layerzerolabs/lz-definitions';
import { getVId } from '../src/app/hashCallDataBuilder/utils';
import { GasolinaAptosSdk } from '../src/app/sdks/gasolinaSdk/aptos';
import { GasolinaSuiSdk } from '../src/app/sdks/gasolinaSdk/sui';
import { GasolinaSolanaSdk } from '../src/app/sdks/gasolinaSdk/solana';
import { GasolinaStarknetSdk } from '../src/app/sdks/gasolinaSdk/starknet';
import { GasolinaTonSdk } from '../src/app/sdks/gasolinaSdk/ton';

type BuildResult = { hashCallData: string; details?: { dvnCallData?: { targetContract?: string; ulnCallData?: string }; dvnHashCallData?: { dvnCallData?: string } } };
const families: Record<string, string[]> = {
    aptos: ['aptos'], initia: ['initia'], movement: ['movement'], sui: ['sui'],
    iotal1: ['iotal1'], solana: ['solana'], starknet: ['starknet'], ton: ['ton', 'tontestnet'],
};
const envs = ['mainnet', 'testnet', 'sandbox'];
const source: Record<string, string> = { mainnet: 'ethereum', testnet: 'sepolia', sandbox: 'ethereum' };
const SENDER = '0x' + '11'.repeat(32), RECEIVER = '0x' + '22'.repeat(32);
const GUID = '0x' + '5a'.repeat(32), MESSAGE = '0x' + 'c0ffee'.repeat(11);
const V2_HASH_INFO = { lookupHash: '0x' + '6c'.repeat(32), blockData: '0x' + '7d'.repeat(32) };
const DVN = '0x' + '33'.repeat(32);
const SOLANA_DVN = '4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4';
const eid = (chain: string, env: string, version: EndpointVersion): number | null => {
    try { return Number(getChainIdForEndpointVersion(chain, env, version)); } catch { return null; }
};
const capture = async (f: () => Promise<BuildResult>) => {
    try {
        const r = await f();
        return { outcome: 'built', hashCallData: r.hashCallData, target: r.details?.dvnCallData?.targetContract,
            ulnCallData: r.details?.dvnCallData?.ulnCallData, dvnCallData: r.details?.dvnHashCallData?.dvnCallData,
            details: r.details };
    } catch (error: unknown) {
        return { outcome: 'refused', httpStatus: 500, errorClass: error instanceof Error ? error.constructor.name : typeof error,
            error: error instanceof Error ? error.message : String(error) };
    }
};
const main = async () => {
    const rows: object[] = [];
    for (const environment of envs) for (const [family, chainNames] of Object.entries(families)) {
        for (const chainName of chainNames) {
            if (!getAvailableChainNames(environment).includes(chainName)) continue;
            const type = StaticChainConfigs.getChainType(chainName);
            let sdk: { buildULNV2VerifyPayload: (...args: never[]) => Promise<BuildResult>; buildULNV3VerifyPayload: (...args: never[]) => Promise<BuildResult>; buildULNReadV1VerifyPayload: (...args: never[]) => Promise<BuildResult> };
            try {
                sdk = (type === ChainType.APTOS || type === ChainType.INITIA ? new GasolinaAptosSdk(environment, chainName, undefined as never)
                    : type === ChainType.SUI || type === ChainType.IOTAMOVE ? new GasolinaSuiSdk(environment, chainName, undefined as never)
                    : type === ChainType.SOLANA ? new GasolinaSolanaSdk(environment, chainName, undefined as never)
                    : type === ChainType.STARKNET ? new GasolinaStarknetSdk(environment, chainName, undefined as never)
                    : new GasolinaTonSdk(environment, chainName, { v2: { open: <T>(contract: T): T => contract }, v3: { open: <T>(contract: T): T => contract } } as never)) as unknown as typeof sdk;
            } catch (error: unknown) { rows.push({ environment, family, chainName, setupError: error instanceof Error ? error.message : String(error) }); continue; }
            const src = source[environment], srcV1 = eid(src, environment, EndpointVersion.V1), srcV2 = eid(src, environment, EndpointVersion.V2);
            const dstV1 = eid(chainName, environment, EndpointVersion.V1), dstV2 = eid(chainName, environment, EndpointVersion.V2);
            let vId: string | null = null, vIdError: object | null = null;
            try { vId = getVId(undefined, chainName, environment); } catch (error: unknown) { vIdError = { errorClass: error instanceof Error ? error.constructor.name : typeof error, error: error instanceof Error ? error.message : String(error) }; }
            const arms: Record<string, unknown> = {};
            const message = (dstEid: number, sendVersion: UlnVersion) => ({ lzMessageId: { pathwayId: { srcEid: srcV2, dstEid, sender: SENDER, receiver: RECEIVER, srcChainName: src, dstChainName: chainName }, nonce: 4242, ulnSendVersion: sendVersion }, guid: GUID, message: MESSAGE });
            const v1Message = { lzMessageId: { pathwayId: { srcEid: srcV1, dstEid: dstV1, sender: SENDER, receiver: RECEIVER, srcChainName: src, dstChainName: chainName }, nonce: 4242, ulnSendVersion: UlnVersion.V2 }, message: MESSAGE };
            const addresses = family === 'solana' || family === 'starknet' || family === 'ton' ? [undefined, family === 'solana' ? SOLANA_DVN : DVN] : [undefined];
            for (const dvnAddress of addresses) {
                const suffix = dvnAddress ? ':withDvnAddress' : '';
                const v = vId ?? '';
                if (dstV1 !== null) {
                    arms['V301' + suffix] = await capture(() => sdk.buildULNV3VerifyPayload(message(dstV1, UlnVersion.V301) as never, 15, 1_760_000_000, v, dvnAddress) as never);
                    if (srcV1 !== null && !dvnAddress) arms.V2 = await capture(() => sdk.buildULNV2VerifyPayload(v1Message as never, V2_HASH_INFO as never, 15, 1_760_000_000, v) as never);
                }
                if (dstV2 !== null) {
                    arms['V302' + suffix] = await capture(() => sdk.buildULNV3VerifyPayload(message(dstV2, UlnVersion.V302) as never, 15, 1_760_000_000, v, dvnAddress) as never);
                    arms['ReadV1002' + suffix] = await capture(() => sdk.buildULNReadV1VerifyPayload(message(dstV2, UlnVersion.ReadV1002) as never, 'ab'.repeat(40), 1_760_000_000, v, dvnAddress) as never);
                }
            }
            rows.push({ environment, family, chainName, chainType: String(type), srcChainName: src, srcEidV1: srcV1, srcEidV2: srcV2, dstEidV1: dstV1, dstEidV2: dstV2, vId, vIdError, arms });
        }
    }
    process.stdout.write(JSON.stringify({ producedBy: { upstream: 'gasolina-audit snapshot 1.2.66', emitter: 'emit-nonevm-destination.ts' }, input: { sender: SENDER, receiver: RECEIVER, guid: GUID, message: MESSAGE, v2HashInfo: V2_HASH_INFO, dvnAddress: DVN, solanaDvnAddress: SOLANA_DVN }, rows }, null, 2) + '\n');
};
main().catch((error: unknown) => { console.error(error); process.exit(1); });
