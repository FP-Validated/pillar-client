// Stage 0a: every chain-type and trusted-address binding upstream gasolina-audit (snapshot 1.2.66)
// derives offline, per environment, family and role. Each value comes from the getter the upstream
// SDK itself calls (cited per role in `roles`); a getter that throws is recorded as that row's error.
// No provider is dialled: TON getters receive an `open` that returns the contract unchanged.
import { EndpointVersion } from '@layerzerolabs/lz-definitions';
import { getEndpointProgramId, getULNProgramId } from '@layerzerolabs/lz-solana-sdk-v2';
import { getNetworkName } from '@offchain-monorepo/chain-utils';
import { getEndpointContractAddress, getUlnV2ContractAddress } from '@offchain-monorepo/layerzero-core-contracts';
import {
    getEndpointV2ContractAddress,
    getReadLib1002ContractAddress,
    getReceiveUln301ContractAddress,
    getReceiveUln302ContractAddress,
    getSendUln301ContractAddress,
    getSendUln302ContractAddress,
    getSimpleMessageLibContractAddress,
} from '@offchain-monorepo/lz-evm-sdk-v2-contracts';
import {
    getEndpointV2ContractAddress as getStarknetEndpointV2Address,
    getUln302ContractAddress as getStarknetUln302Address,
} from '@offchain-monorepo/lz-starknet-sdk';
import {
    getEndpointV2ContractAddress as getStellarEndpointV2Address,
    getLayerZeroViewsContractAddress as getStellarLayerZeroViewsAddress,
    getUln302ContractAddress as getStellarUln302Address,
} from '@offchain-monorepo/lz-stellar-sdk';
// `lz-canton-sdk` imports deployment artifacts the snapshot does not carry, so its getters
// cannot load; they return `STATIC_VE3_CONTRACT_ADDRESSES[CONTRACT_KEYS[name]]` with
// `CONTRACT_KEYS = { EndpointV2: 'endpointV2', Uln302: 'uln302' }`
// (packages/contracts/lz-canton-sdk/src/contractGetters.ts:25-36), read here at the source.
import { STATIC_VE3_CONTRACT_ADDRESSES } from '@layerzerolabs/ver-address';
import { getControllerContract, getDeprecatedUlnManagerContract, getUlnManagerContract } from '@offchain-monorepo/lz-ton-contracts';
import { getMoveContractAccountAddress, LayerZeroAccounts } from '@offchain-monorepo/move-contracts';
import { getSuiContractAccountAddress, SuiLayerZeroAccounts } from '@offchain-monorepo/sui-contracts';
import {
    getAvailableChainNames,
    getChainIdForEndpointVersion,
    getNonEvmEndpointId,
    StaticChainConfigs,
} from '@offchain-monorepo/static-config';
import {
    getAptosV1LayerZeroAddress,
    getAptosV1OracleAddress,
    getAptosV1Uln301Address,
} from '@offchain-monorepo/lz-v1-sdk/src/aptos/addresses';

const ENVIRONMENTS = ['mainnet', 'testnet', 'sandbox', 'localnet'];
const EXCLUDED: Record<string, true> = {};
const offlineTon = { open: (contract: any) => contract } as any;

const value = (fn: () => unknown) => {
    try {
        const v = fn();
        if (v === undefined || v === null) return { error: 'undefined' };
        return { value: String(v) };
    } catch (error) {
        return { error: String((error as Error)?.message ?? error).slice(0, 200) };
    }
};

const eid = (chain: string, env: string, version: EndpointVersion, nonEvm: boolean) =>
    value(() => (nonEvm ? getNonEvmEndpointId(chain, env, version) : getChainIdForEndpointVersion(chain, env, version)));

const rolesFor = (chain: string, env: string, chainType: string): Record<string, { value?: string; error?: string }> => {
    switch (chainType) {
        case 'EVM':
        case 'TRON':
            return {
                // Source PacketSent emitter for V302/V300/ReadV1002 sends (endpoint/evm/index.ts:668-677).
                EndpointV2: value(() => getEndpointV2ContractAddress(chain, env)),
                Endpoint: value(() => getEndpointContractAddress(chain, env)),
                // getUlnVersionFromAddress table (endpoint/evm/decoders/index.ts:49-93).
                SendUln302: value(() => getSendUln302ContractAddress(chain, env)),
                SendUln301: value(() => getSendUln301ContractAddress(chain, env)),
                SimpleMessageLib: value(() => getSimpleMessageLibContractAddress(chain, env)),
                // Destination targets (gasolinaSdk/evm/index.ts:22-29,63).
                ReceiveUln302: value(() => getReceiveUln302ContractAddress(chain, env)),
                ReceiveUln301: value(() => getReceiveUln301ContractAddress(chain, env)),
                ReadLib1002: value(() => getReadLib1002ContractAddress(chain, env)),
                UltraLightNodeV2: value(() => getUlnV2ContractAddress(chain, env)),
            };
        case 'APTOS':
        case 'INITIA':
            return {
                // endpoint/aptos/index.ts:107-118, gasolinaSdk/aptos/index.ts:25-32,162-174.
                ENDPOINT: value(() => getMoveContractAccountAddress(chain, env, LayerZeroAccounts.ENDPOINT)),
                ULN_302: value(() => getMoveContractAccountAddress(chain, env, LayerZeroAccounts.ULN_302)),
                LAYERZERO_VIEWS: value(() => getMoveContractAccountAddress(chain, env, LayerZeroAccounts.LAYERZERO_VIEWS)),
                V1_ULN_301: value(() => getAptosV1Uln301Address(env)),
                V1_ORACLE: value(() => getAptosV1OracleAddress(env)),
                // Legacy ULNv2 source: `${layerzero}::packet_event::OutboundEvent` (lz-v1-sdk/src/aptos/aptos.ts:913-950).
                V1_LAYERZERO: value(() => getAptosV1LayerZeroAddress(env)),
            };
        case 'SUI':
        case 'IOTAMOVE':
            return Object.fromEntries(
                [
                    'ENDPOINT',
                    'ULN_302',
                    'ULN_302_VERIFICATION',
                    'L0_VIEWS',
                    'UTILS',
                    'ENDPOINT_V2_COMMON',
                ].map((account) => [account, value(() => getSuiContractAccountAddress(chain, env, (SuiLayerZeroAccounts as any)[account]))]),
            );
        case 'SOLANA':
            return {
                // endpoint/solana/index.ts:103-118; gasolinaSdk/solana/index.ts:147-153.
                EndpointProgram: value(() => getEndpointProgramId(getNetworkName(chain, env) as never).toBase58()),
                UlnProgram: value(() => getULNProgramId(getNetworkName(chain, env) as never).toBase58()),
            };
        case 'STARKNET':
            return {
                // endpoint/starknet/index.ts:91; gasolinaSdk/starknet/index.ts:51-56.
                EndpointV2: value(() => getStarknetEndpointV2Address(chain, env)),
                UltraLightNode302: value(() => getStarknetUln302Address(chain, env)),
            };
        case 'STELLAR':
            return {
                // endpoint/stellar/index.ts; gasolinaSdk/stellar/index.ts:10,137; uln/stellar/index.ts:94-102.
                EndpointV2: value(() => getStellarEndpointV2Address(chain, env)),
                Uln302: value(() => getStellarUln302Address(chain, env)),
                LayerZeroViews: value(() => getStellarLayerZeroViewsAddress(chain, env)),
            };
        case 'CANTON':
            return {
                // endpoint/canton/index.ts:62; gasolinaSdk/canton/index.ts:81,137.
                EndpointV2: value(() => STATIC_VE3_CONTRACT_ADDRESSES.endpointV2),
                Uln302: value(() => STATIC_VE3_CONTRACT_ADDRESSES.uln302),
            };
        case 'TON':
            return {
                // endpoint/ton/index.ts:84; gasolinaSdk/ton/index.ts:35-40.
                Controller: value(() => getControllerContract(chain, env, offlineTon).address.toRawString()),
                UlnManager: value(() => getUlnManagerContract(chain, env, offlineTon).address.toRawString()),
                DeprecatedUlnManager: value(() => getDeprecatedUlnManagerContract(chain, env, offlineTon).address.toRawString()),
            };
        default:
            return {};
    }
};

const NON_EVM_NAMES = ['aptos', 'movement', 'initia', 'sui', 'iotal1', 'solana', 'starknet', 'ton', 'stellar', 'canton'];

const main = async () => {
    const rows: any[] = [];
    for (const env of ENVIRONMENTS) {
        let catalog: string[] = [];
        let catalogError: string | undefined;
        try {
            catalog = getAvailableChainNames(env);
        } catch (error) {
            catalogError = String((error as Error).message);
        }
        const names = [...new Set([...catalog, ...NON_EVM_NAMES])].filter((c) => !EXCLUDED[c]).sort();
        for (const chain of names) {
            const chainType = String(StaticChainConfigs.getChainType(chain));
            const nonEvm = !['EVM', 'TRON'].includes(chainType);
            rows.push({
                environment: env,
                chainName: chain,
                inCatalog: catalog.includes(chain),
                catalogError,
                chainType,
                eidV1: eid(chain, env, EndpointVersion.V1, nonEvm),
                eidV2: eid(chain, env, EndpointVersion.V2, nonEvm),
                roles: rolesFor(chain, env, chainType),
            });
        }
    }
    // Chain type for every name Pillar's static table carries, so a name upstream types
    // differently (or does not know) is a row, not an omission.
    const pillarNames: string[] = JSON.parse(
        require('fs').readFileSync(require('path').join(__dirname, 'pillar-static-chain-names.json'), 'utf8'),
    );
    const chainTypes = Object.fromEntries(pillarNames.map((name) => [name, String(StaticChainConfigs.getChainType(name))]));
    process.stdout.write(
        JSON.stringify(
            {
                producedBy: {
                    upstream: 'gasolina-audit snapshot 1.2.66 (manifest sha256 8ad87eb6...; commit 213cd500 label unverified)',
                    generator: 'scripts/gasolina-parity/emit-chain-bindings.ts',
                    excluded: Object.keys(EXCLUDED),
                },
                chainTypes,
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
