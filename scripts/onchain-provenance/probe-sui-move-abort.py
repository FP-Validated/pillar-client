import base64, json, urllib.request

SUI_GQL = "https://graphql.mainnet.sui.io/graphql"
IOTA_RPC = "https://api.mainnet.iota.cafe"
SUI = dict(utils="0x00245ba36f7a1cc643a2b037450dff1e4399e18069c6545fb5fcaaf37d39d7dc",
           uln="0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0",
           verification="0x950f66ed27ec0a01a52bda147d74165d4cc20165f0cee0ecae6aaacde13d7741")
IOTA = dict(utils="0x56a262afe5db9b34426f343160481290d010551ca15b427b1fb4b0010e3b69ed",
            uln="0x042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e",
            verification="0x7080ff946569bcdb73283d6287ee9d57692331625c13eebf0f1bdd878986333d")
SENDER = "0x" + "12345678" * 8


def post(url, body):
    request = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json", "user-agent": "pillar-probe"})
    return json.load(urllib.request.urlopen(request, timeout=30))


def bcs_bytes(raw):
    return bytes([len(raw)]) + raw


def sui_shared_version(object_id):
    q = "query($id: SuiAddress!) { object(address: $id) { owner { ... on Shared { initialSharedVersion } } } }"
    return post(SUI_GQL, {"query": q, "variables": {"id": object_id}})["data"]["object"]["owner"]["initialSharedVersion"]


def sui_case(header_hash, payload_hash):
    version = sui_shared_version(SUI["verification"])
    pure = lambda raw: {"kind": "PURE", "pure": base64.b64encode(raw).decode()}
    tx = {"sender": SENDER, "kind": {"programmableTransaction": {
        "inputs": [{"kind": "SHARED", "objectId": SUI["verification"], "version": str(version), "mutable": False},
                   pure(bytes.fromhex("ab" * 32)), pure(bcs_bytes(header_hash)), pure(bcs_bytes(payload_hash))],
        "commands": [
            {"moveCall": {"package": SUI["utils"], "module": "bytes32", "function": "from_bytes", "typeArguments": [], "arguments": [{"kind": "INPUT", "input": 2}]}},
            {"moveCall": {"package": SUI["utils"], "module": "bytes32", "function": "from_bytes", "typeArguments": [], "arguments": [{"kind": "INPUT", "input": 3}]}},
            {"moveCall": {"package": SUI["uln"], "module": "uln_302", "function": "get_confirmations", "typeArguments": [],
                          "arguments": [{"kind": "INPUT", "input": 0}, {"kind": "INPUT", "input": 1}, {"kind": "RESULT", "result": 0}, {"kind": "RESULT", "result": 1}]}}]}}}
    q = ("query($transaction: JSON!) { simulateTransaction(transaction: $transaction, checksEnabled: false, doGasSelection: true) "
         "{ effects { status executionError { message abortCode sourceLineNumber instructionOffset identifier constant module { name package { address } } function { name } } } } }")
    return post(SUI_GQL, {"query": q, "variables": {"transaction": tx}})


out = {"sui": {
    "missing": sui_case(b"\x11" * 32, b"\x22" * 32),
    "short_header_hash": sui_case(b"\x11" * 31, b"\x22" * 32),
}}
print(json.dumps(out, indent=1))
json.dump(out, open("/tmp/m27-move/sui.json", "w"), indent=1)
