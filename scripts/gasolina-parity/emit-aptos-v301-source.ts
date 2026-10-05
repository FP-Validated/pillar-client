import { readFileSync } from 'node:fs';

import { getMatchingEventsInTransaction } from '@offchain-monorepo/common-move';
import { extractLZEventFromPacketSentEvent } from '@offchain-monorepo/lz-v2-sdk/src/endpoint/aptos/decoders';
import { Uln301Modules, EndpointV2EventResources } from '@offchain-monorepo/move-contracts';
import { getAptosV1Uln301Address } from '@offchain-monorepo/lz-v1-sdk';

const transaction = JSON.parse(readFileSync('parity-aptosmove/aptos_v301_source_tx.json', 'utf8'));
const block = {
    block_height: Number(transaction.version),
    block_hash: transaction.hash,
};
const eventToken =
    getAptosV1Uln301Address('mainnet') + '::' + Uln301Modules.sending + '::' + EndpointV2EventResources.PacketSent;
const events = getMatchingEventsInTransaction(
    'aptos',
    transaction,
    eventToken,
    (event) => extractLZEventFromPacketSentEvent('aptos', 'mainnet', event),
    block,
);
if (events.length !== 1) throw new Error('Expected one upstream V301 event; got ' + events.length);
console.log(JSON.stringify({ eventToken, event: events[0] }, null, 2));