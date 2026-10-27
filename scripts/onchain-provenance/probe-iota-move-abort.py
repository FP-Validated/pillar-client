import base64, json, struct, urllib.request

IOTA_RPC = "https://api.mainnet.iota.cafe"
IOTA = dict(utils="0x56a262afe5db9b34426f343160481290d010551ca15b427b1fb4b0010e3b69ed",
            uln="0x042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e",
            verification="0x7080ff946569bcdb73283d6287ee9d57692331625c13eebf0f1bdd878986333d")
SENDER = "0x" + "12345678" * 8


def rpc(method, params):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    request = urllib.request.Request(IOTA_RPC, json.dumps(body).encode(), {"content-type": "application/json", "user-agent": "pillar-probe"})
    return json.load(urllib.request.urlopen(request, timeout=30))


def uleb(n):
    out = b""
    while True:
        byte = n & 0x7F
        n >>= 7
        out += bytes([byte | (0x80 if n else 0)])
        if not n:
            return out


def vec(items):
    return uleb(len(items)) + b"".join(items)


def string(s):
    return uleb(len(s)) + s.encode()


def addr(a):
    return bytes.fromhex(a[2:].rjust(64, "0"))


def pure(raw):
    return b"\x00" + vec([bytes([b]) for b in raw])


def shared(object_id, version):
    return b"\x01" + b"\x01" + addr(object_id) + struct.pack("<Q", version) + b"\x00"


def move_call(package, module, function, args):
    return b"\x00" + addr(package) + string(module) + string(function) + vec([]) + vec(args)


def inp(i):
    return b"\x01" + struct.pack("<H", i)


def res(i):
    return b"\x02" + struct.pack("<H", i)


def bcs_bytes(raw):
    return uleb(len(raw)) + raw


def case(header_hash, payload_hash):
    owner = rpc("iota_getObject", [IOTA["verification"], {"showOwner": True}])["result"]["data"]["owner"]["Shared"]
    version = int(owner["initial_shared_version"])
    kind = b"\x00" + vec([
        shared(IOTA["verification"], version),
        pure(bytes.fromhex("ab" * 32)),
        pure(bcs_bytes(header_hash)),
        pure(bcs_bytes(payload_hash)),
    ]) + vec([
        move_call(IOTA["utils"], "bytes32", "from_bytes", [inp(2)]),
        move_call(IOTA["utils"], "bytes32", "from_bytes", [inp(3)]),
        move_call(IOTA["uln"], "uln_302", "get_confirmations", [inp(0), inp(1), res(0), res(1)]),
    ])
    response = rpc("iota_devInspectTransactionBlock", [SENDER, base64.b64encode(kind).decode(), None, None])
    result = response.get("result", response)
    return {"error": result.get("error"), "status": (result.get("effects") or {}).get("status")}


out = {"iota": {"missing": case(b"\x11" * 32, b"\x22" * 32), "short_header_hash": case(b"\x11" * 31, b"\x22" * 32)}}
print(json.dumps(out, indent=1))
json.dump(out, open("/tmp/m27-move/iota.json", "w"), indent=1)
