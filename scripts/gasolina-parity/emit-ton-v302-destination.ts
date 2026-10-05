import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { getUlnConnectionContractFromConstructor, getUlnContractFromConstructor, getUlnManagerContract, getDeprecatedUlnManagerContract, DEPRECATED_ULN_OAPPS } from '@monorepo/lz-ton-contracts';
import { buildDvnVerifyCallData } from '@monorepo/lz-ton-contracts/src/dvn';
import { addressToHex, parseTonAddress } from '@monorepo/common-ton';
import { GasolinaTonSdk } from '../src/app/sdks/gasolinaSdk/ton';
import { UlnVersion } from '@monorepo/common-model';

const openOnly = { open: <T>(contract: T): T => contract };
const openOnlyProviders = { v2: openOnly, v3: openOnly };
let providerGetStateCalls = 0;
const trackedProvider = {
  open<T extends object>(contract: T): T {
    return new Proxy(contract, { get(target, property, receiver) {
      if (property === 'getState') providerGetStateCalls += 1;
      return Reflect.get(target, property, receiver);
    } });
  },
};
const provider = { v2: trackedProvider, v3: trackedProvider } as never;
const sender = '0x' + '11'.repeat(32), receiver = '0x' + '22'.repeat(32);
const guid = '0x' + '5a'.repeat(32), message = '0x' + 'c0ffee'.repeat(11);
const dvnAddress = '0x' + '33'.repeat(32);
const emitterSha256 = createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex');
const vectors = [
  { environment: 'mainnet', srcChainName: 'ethereum', srcEid: 30101, dstEid: 30343, vId: '343' },
  { environment: 'sandbox', srcChainName: 'ethereum', srcEid: 50121, dstEid: 50343, vId: '20343' },
];
const outputs = [] as unknown[];
// tsx compiles emitters to CommonJS, which has no top-level await.
const main = async () => {
for (const vector of vectors) {
  const currentManager = getUlnManagerContract('ton', vector.environment, openOnly as never);
  const deprecatedManager = getDeprecatedUlnManagerContract('ton', vector.environment, openOnly as never);
  const isDeprecatedUln = DEPRECATED_ULN_OAPPS.includes(receiver);
  const manager = isDeprecatedUln ? deprecatedManager : currentManager;
  const path = { srcEid: vector.srcEid, dstEid: vector.dstEid, sender, receiver, srcChainName: vector.srcChainName, dstChainName: 'ton' };
  const lzMessage = { lzMessageId: { pathwayId: path, nonce: 4242, ulnSendVersion: UlnVersion.V302 }, guid, message } as never;
  const uln = getUlnContractFromConstructor(openOnlyProviders as never, { path: path as never, ulnManagerAddress: manager.address }, isDeprecatedUln);
  const ulnConnection = getUlnConnectionContractFromConstructor(openOnlyProviders as never, { path: path as never, ulnManagerAddress: manager.address }, isDeprecatedUln);
  const implementation = parseTonAddress(dvnAddress);
  const { ulnCallData, dvnVerifyCallData, packetHash } = buildDvnVerifyCallData({ uln, ulnConnection, lzMessage, blockConfirmation: 15, expiration: 1_760_000_000, dvnAddressImplementation: implementation } as never);
  let missingAddress: unknown;
  const sdk = new GasolinaTonSdk(vector.environment, 'ton', provider);
  try {
    await sdk.buildULNV3VerifyPayload(lzMessage as never, 15, 1_760_000_000, vector.vId, undefined);
    missingAddress = { outcome: 'unexpected-build' };
  } catch (error) {
    const e = error as Error;
    missingAddress = { errorClass: e.constructor.name, message: e.message, stackFrames: (e.stack ?? '').split('\n').slice(1, 5).map((line) => line.trim()), providerGetStateCalls };
  }
  outputs.push({
    environment: vector.environment,
    chainName: 'ton',
    srcEid: vector.srcEid,
    dstEid: vector.dstEid,
    vId: vector.vId,
    ulnManagerAddress: manager.address.toString(),
    deprecatedUlnManagerAddress: deprecatedManager.address.toString(),
    derived: { ulnAddress: uln.address.toString(), ulnConnectionAddress: ulnConnection.address.toString() },
    implementationBranch: { name: 'not-deployed/not-a-proxy', implementationAddress: implementation.toString(), modeledFrom: 'lz-ton-contracts getImplementationContract not-deployed/not-a-proxy branch: parseTonAddress(dvnAddress)' },
    built: { hashCallData: dvnVerifyCallData.hash().toString('hex'), targetContract: addressToHex(uln.address), ulnCallDataBoc: ulnCallData.toBoc().toString('hex'), dvnCallDataBoc: dvnVerifyCallData.toBoc().toString('hex'), packetHash },
    missingDvnAddress: missingAddress,
  });
}
process.stdout.write(JSON.stringify({ producedBy: { upstream: 'gasolina-audit snapshot 1.2.66', emitter: 'emit-ton-v302-destination.ts', emitterSha256 }, input: { sender, receiver, guid, message, nonce: 4242, blockConfirmation: 15, expiration: 1_760_000_000, dvnAddress }, vectors: outputs }, null, 2) + '\n');
};
main().catch((error: unknown) => { console.error(error instanceof Error ? error.stack : String(error)); process.exitCode = 1; });
