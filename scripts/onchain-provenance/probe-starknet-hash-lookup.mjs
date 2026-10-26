// Confirms the deployed Starknet ULN302 hash_lookup storage layout against live state:
// for recent PayloadVerified events, the computed storage slots must hold
// {submitted, confirmations} and agree with has_payload_signed.
import { hash, ec, num } from 'starknet';
import { keccak_256 } from '@noble/hashes/sha3';

const RPC = process.env.RPC ?? 'https://starknet-rpc.publicnode.com';
const ULN = '0x0727f40349719ac76861a51a0b3d3e07be1577fff137bb81a5dc32e5a5c61d38';
let id = 0;
async function rpc(method, params) {
  const res = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}
const ped = (a, b) => BigInt(ec.starkCurve.pedersen(BigInt(a), BigInt(b)));
const MASK128 = (1n << 128n) - 1n;
const ADDR_BOUND = (1n << 251n) - 256n;
function slot(headerHash, payloadHash, dvn) {
  let s = BigInt(hash.starknetKeccak('hash_lookup'));
  for (const v of [headerHash, payloadHash]) { s = ped(s, v & MASK128); s = ped(s, v >> 128n); }
  s = ped(s, BigInt(dvn));
  return s % ADDR_BOUND;
}
// ByteArray serde: [n_full_words, ...words(31 bytes), pending_word, pending_len]
function byteArray(felts, start) {
  const n = Number(BigInt(felts[start]));
  let bytes = [];
  for (let i = 0; i < n; i++) bytes.push(...Buffer.from(BigInt(felts[start + 1 + i]).toString(16).padStart(62, '0'), 'hex'));
  const pending = BigInt(felts[start + 1 + n]);
  const plen = Number(BigInt(felts[start + 2 + n]));
  if (plen) bytes.push(...Buffer.from(pending.toString(16).padStart(plen * 2, '0'), 'hex'));
  return { bytes: Buffer.from(bytes), next: start + 3 + n };
}
const selector = hash.getSelectorFromName('PayloadVerified');
const latest = await rpc('starknet_blockNumber', []);
const out = [];
let token;
let scanned = 0;
for (let page = 0; page < 200 && out.filter((r) => r.hasPayloadSigned === '1').length < 6; page++) {
  const ev = await rpc('starknet_getEvents', [{ address: ULN, keys: [[selector]], from_block: { block_number: Number(process.env.FROM ?? latest - 2000000) }, to_block: 'latest', chunk_size: 100, ...(token ? { continuation_token: token } : {}) }]);
  for (const e of ev.events) {
    // PayloadVerified { dvn, header: ByteArray, confirmations: u256, proof_hash: Bytes32 } (all in data)
    const d = e.data;
    const dvn = e.keys[1];
    const { bytes: header, next } = byteArray(d, 0);
    const confirmations = BigInt(d[next]) + (BigInt(d[next + 1]) << 128n);
    const payloadHash = BigInt(d[next + 2]) + (BigInt(d[next + 3]) << 128n);
    const headerHash = BigInt('0x' + Buffer.from(keccak_256(header)).toString('hex'));
    const base = slot(headerHash, payloadHash, dvn);
    const [submitted, stored] = await Promise.all([0n, 1n].map((o) => rpc('starknet_getStorageAt', [ULN, num.toHex(base + o), 'latest'])));
    const signed = await rpc('starknet_call', [{ contract_address: ULN, entry_point_selector: hash.getSelectorFromName('has_payload_signed'),
      calldata: [headerHash & MASK128, headerHash >> 128n, payloadHash & MASK128, payloadHash >> 128n, BigInt(dvn)].map((v) => num.toHex(v)) }, 'latest']);
    scanned++;
    if (BigInt(signed[0]) === 0n && BigInt(submitted) === 0n && BigInt(stored) === 0n) continue;
    const srcEid = header.readUInt32BE(9);
    const receiver = BigInt('0x' + header.subarray(49, 81).toString('hex'));
    const config = await rpc('starknet_call', [{ contract_address: ULN, entry_point_selector: hash.getSelectorFromName('get_oapp_uln_receive_config'),
      calldata: [num.toHex(receiver), num.toHex(srcEid)] }, 'latest']);
    out.push({ block: e.block_number, tx: e.transaction_hash, dvn, header: '0x' + header.toString('hex'),
      headerHash: num.toHex(headerHash), payloadHash: num.toHex(payloadHash), slot: num.toHex(base),
      receiver: num.toHex(receiver), srcEid, receiveConfig: config,
      eventConfirmations: confirmations.toString(),
      storageSubmitted: BigInt(submitted).toString(), storageConfirmations: BigInt(stored).toString(), hasPayloadSigned: BigInt(signed[0]).toString() });
    if (out.filter((r) => r.hasPayloadSigned === '1').length >= 6) break;
  }
  token = ev.continuation_token;
  if (!token) break;
}
console.log(JSON.stringify({ rpc: RPC, uln: ULN, latestBlock: latest, scanned, rows: out }, null, 2));
