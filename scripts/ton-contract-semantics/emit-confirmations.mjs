// Runs the pinned UlnConnection code (the mainnet deployment, from
// crates/pillar-config/src/generated_ton_layerzero.rs) in a TVM emulator and records
// what the contract itself says about a DVN attestation at, above and below the
// pathway's required confirmations. The output is the M-22 parity anchor in
// crates/pillar-runtime/tests/ton_contract_semantics/confirmations.json.
//
//   npm install @ton/core@0.63.1 @ton/crypto@3.3.0 @ton/sandbox@0.45.0 @ton/test-utils@0.12.0 --legacy-peer-deps
//   node scripts/ton-contract-semantics/emit-confirmations.mjs <repo-root> > confirmations.json
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Address, Cell, Dictionary, beginCell, toNano } from '@ton/core';
import { Blockchain, createShardAccount } from '@ton/sandbox';

const root = process.argv[2];
const read = (path) => readFileSync(join(root, path), 'utf8');
const code = Cell.fromBoc(
  Buffer.from(/\("UlnConnection", "([0-9a-f]+)"\)/.exec(read('crates/pillar-config/src/generated_ton_layerzero.rs'))[1], 'hex'),
)[0];
const payloadSigned = read('crates/pillar-layerzero/src/other_non_evm/ton/payload_signed.rs');
const liveConnection = Cell.fromBase64(/const LIVE_ULN_CONNECTION_STORAGE: &str = "([^"]+)"/.exec(payloadSigned)[1]);
const livePacket = Cell.fromBase64(/pub const LIVE_TON_PACKET_BOC: &str = "([^"]+)"/.exec(payloadSigned)[1]);
const liveUln = Cell.fromBase64(read('crates/pillar-runtime/tests/onchain_provenance/ton_mainnet_uln_storage.b64').trim());

// `clDeclare` for single-cell classes, the shape of every class written here.
function clDeclare(name, fields) {
  const header = beginCell().storeUint(BigInt('0x' + Buffer.from(name).toString('hex')), 80);
  const data = beginCell();
  let offset = 350;
  let refOffset = 0;
  for (const field of fields) {
    if (field.ref) {
      header.storeUint(9, 4).storeUint(0, 2).storeUint(1023, 10).storeUint(refOffset++, 2);
      data.storeRef(field.ref);
    } else {
      const bits = 1 << field.t;
      header.storeUint(field.t, 4).storeUint(0, 2).storeUint(offset, 10).storeUint(3, 2);
      data.storeUint(field.v, bits);
      offset += bits;
    }
  }
  while (header.bits < 350) header.storeBit(1);
  return header.storeBuilder(data).endCell();
}
const addressList = (addresses) => addresses.reduce((b, a) => b.storeUint(a, 256), beginCell()).endCell();
const receiveConfig = ({ confirmationsNull, confirmations, required }) =>
  clDeclare('UlnRecvCfg', [
    { t: 0, v: 1 }, { t: 5, v: 0 },
    { t: 0, v: confirmationsNull ? 1 : 0 }, { t: 6, v: confirmations },
    { t: 0, v: 0 }, { ref: addressList(required) },
    { t: 0, v: 0 }, { ref: addressList([]) },
    { t: 3, v: 0 },
  ]);
const attestation = (hash, confirmations) => clDeclare('Attest', [{ t: 8, v: hash }, { t: 6, v: confirmations }]);

function fieldInfo(cell, index) {
  const s = cell.beginParse();
  s.skip(80 + index * 18 + 4);
  const cellId = s.loadUint(2);
  const offset = s.loadUint(10);
  return { cellId, offset, refIdx: s.loadUint(2) };
}
function replaceRef(cell, refIdx, value) {
  const b = beginCell().storeBits(cell.bits);
  cell.refs.forEach((ref, i) => b.storeRef(i === refIdx ? value : ref));
  return b.endCell();
}
function clSetRef(cell, index, value) {
  const { cellId, refIdx } = fieldInfo(cell, index);
  return cellId === 0
    ? replaceRef(cell, refIdx, value)
    : replaceRef(cell, cellId, replaceRef(cell.refs[cellId], refIdx, value));
}
function clGetUint(cell, index, width) {
  const { cellId, offset } = fieldInfo(cell, index);
  const s = (cellId === 0 ? cell : cell.refs[cellId]).beginParse();
  s.skip(offset);
  return s.loadUintBig(width);
}

const DVN = BigInt('0x' + 'aa'.repeat(32));
// A second required DVN that never attests keeps `committableView` at VERIFYING,
// so only this DVN's own attestation decides the already-signed answer.
const ABSENT_DVN = BigInt('0x' + 'bb'.repeat(32));
const required = [DVN, ABSENT_DVN];
const nonce = clGetUint(liveConnection, 4, 64) + 1n;
// `lz::Packet { path, message, nonce, guid }`, rebuilt so the attested packet's own
// nonce is the nonce it is attested under.
const packetAt = (packetNonce) =>
  clDeclare('Packet', [
    { ref: livePacket.refs[0] }, { ref: livePacket.refs[1] },
    { t: 6, v: packetNonce }, { t: 8, v: clGetUint(livePacket, 3, 256) },
  ]);
if (!packetAt(nonce - 1n).equals(livePacket)) throw new Error('Packet rebuild does not reproduce the live packet');
const packet = packetAt(nonce);
const packetHash = BigInt('0x' + packet.hash().toString('hex'));
const address = Address.parse('0:168B0D4BC86F5F148DDC86AEE8D8A9AF61D75C82E8C4509A14C8C0377DA8AD79');
const blockchain = await Blockchain.create();

const cases = [
  ['below_custom', 0n, { confirmationsNull: false, confirmations: 5n }, { confirmationsNull: false, confirmations: 1n }],
  ['one_below_custom', 4n, { confirmationsNull: false, confirmations: 5n }, { confirmationsNull: false, confirmations: 1n }],
  ['equal_custom', 5n, { confirmationsNull: false, confirmations: 5n }, { confirmationsNull: false, confirmations: 9n }],
  ['above_custom', 6n, { confirmationsNull: false, confirmations: 5n }, { confirmationsNull: false, confirmations: 9n }],
  ['custom_null_below_default', 4n, { confirmationsNull: true, confirmations: 0n }, { confirmationsNull: false, confirmations: 5n }],
  ['custom_null_equal_default', 5n, { confirmationsNull: true, confirmations: 0n }, { confirmationsNull: false, confirmations: 5n }],
  ['default_null_flag_ignored', 3n, { confirmationsNull: true, confirmations: 0n }, { confirmationsNull: true, confirmations: 3n }],
  ['zero_required_zero_stored', 0n, { confirmationsNull: false, confirmations: 0n }, { confirmationsNull: false, confirmations: 0n }],
];

const out = [];
for (const [name, stored, custom, fallback] of cases) {
  const perDvn = Dictionary.empty(Dictionary.Keys.BigUint(256), Dictionary.Values.Cell());
  perDvn.set(DVN, attestation(packetHash, stored));
  const lookups = Dictionary.empty(Dictionary.Keys.BigUint(256), Dictionary.Values.Cell());
  lookups.set(nonce, beginCell().storeDictDirect(perDvn).endCell());
  const customConfig = receiveConfig({ ...custom, required });
  const defaultConfig = receiveConfig({ ...fallback, required });
  let connection = clSetRef(liveConnection, 8, beginCell().storeDictDirect(lookups).endCell());
  connection = clSetRef(connection, 7, customConfig);
  const uln = clSetRef(liveUln, 3, defaultConfig);
  await blockchain.setShardAccount(address, createShardAccount({ address, code, data: connection, balance: toNano('1') }));
  const committable = await blockchain.runGetMethod(address, 'committableView', [
    { type: 'int', value: nonce }, { type: 'cell', cell: packet }, { type: 'cell', cell: defaultConfig },
  ]);
  const requiredConfirmations = custom.confirmationsNull ? fallback.confirmations : custom.confirmations;
  const verified = async (threshold) =>
    (await blockchain.runGetMethod(address, 'verifiedView', [
      { type: 'int', value: DVN }, { type: 'int', value: nonce },
      { type: 'int', value: packetHash }, { type: 'int', value: threshold },
    ])).stackReader.readBigNumber() !== 0n;
  out.push({
    name,
    storedConfirmations: Number(stored),
    requiredConfirmations: Number(requiredConfirmations),
    connectionStorageBoc: connection.toBoc().toString('base64'),
    ulnStorageBoc: uln.toBoc().toString('base64'),
    committableView: committable.stackReader.readNumber(),
    verifiedViewAtRequired: await verified(requiredConfirmations),
  });
}

process.stdout.write(JSON.stringify({
  description: 'UlnConnection committableView/verifiedView for one DVN attestation against the pathway requirement, from the pinned mainnet UlnConnection code in @ton/sandbox. A second required DVN never attests, so committableView stays VERIFYING and verifiedView alone is the contract\'s answer for this DVN.',
  generator: 'scripts/ton-contract-semantics/emit-confirmations.mjs',
  emulator: '@ton/sandbox 0.45.0, @ton/core 0.63.1',
  codeHash: code.hash().toString('hex'),
  verifier: '0x' + 'aa'.repeat(32),
  nonce: Number(nonce),
  packetBoc: packet.toBoc().toString('base64'),
  packetHash: packetHash.toString(16).padStart(64, '0'),
  cases: out,
}, null, 2) + '\n');
