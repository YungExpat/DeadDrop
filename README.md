# DeadDrop

**An anonymous P2P encrypted message drop on Trac/Intercom.**

DeadDrop lets a sender post an encrypted message addressed to a recipient's public key. The recipient picks it up over Intercom sidechannels — no server, no identity leakage, no middleman. The sender never knows when the message was picked up. The recipient never reveals their IP to the sender.

## Features

- **Asymmetric encryption** using sealed-box (recipient's public key only)
- **P2P delivery** via Trac/Hyperswarm (no central server)
- **Anonymous** — senders don't need to identify themselves
- **TTL support** — drops auto-expire after a configurable time
- **SC-Bridge compatible** — agent-friendly WebSocket control interface

## Setup & Run

### Prerequisites
- **Node.js 22.x or 23.x** (avoid 24.x)
- **Pear runtime**: `npm install -g pear`
- This repository (fork from Trac-Systems/intercom)

### Quick Start

1. Clone and install:
```bash
git clone https://github.com/YOUR_USERNAME/DeadDrop.git
cd DeadDrop
npm install
```

2. Get your DeadDrop address (start as admin peer):
```bash
pear run . --peer-store-name admin --msb-store-name admin-msb
```
In the output, copy your **Peer pubkey (hex)** — this is **your DeadDrop address** to share with others.

3. In another terminal, join the network (as a different peer):
```bash
pear run . --peer-store-name joiner --msb-store-name joiner-msb \
  --subnet-bootstrap <admin-peer-writer-key-hex>
```

## How It Works

### Sending a Drop
1. Get the recipient's **DeadDrop address** (their peer public key)
2. Encrypt your message using their address with sealed-box encryption
3. Broadcast the encrypted message to the `deaddrop-main` sidechannel
4. No one can decrypt it except the holder of the corresponding private key

### Receiving a Drop
1. Your **DeadDrop address** is your peer's public key
2. Share this address with people who want to send you messages
3. Messages are encrypted and broadcast publicly; only you can decrypt them with your private key
4. No IP leakage — recipients don't reveal themselves to senders

## SC-Bridge Commands

DeadDrop offers these WebSocket commands (via SC-Bridge) for agent integration:

### Start SC-Bridge Server

```bash
pear run . --peer-store-name agent --msb-store-name agent-msb \
  --sc-bridge 1 --sc-bridge-token mytoken123
```

Then connect via WebSocket to `ws://127.0.0.1:49222`

### Message: `auth`
Authenticate with the SC-Bridge.
```json
{"type": "auth", "token": "mytoken123"}
```
Response:
```json
{"type": "auth_ok"}
```

### Message: `identity`
Get your DeadDrop address (peer public key).
```json
{"type": "identity", "id": 1}
```
Response:
```json
{"id": 1, "type": "identity", "address": "3dc6958d834256c4b45feb3de860a4810d5428caefa31f59147af458e980595ec"}
```

### Message: `drop`
Encrypt and send a message to a recipient's public key.
```json
{
  "type": "drop",
  "recipientPubKey": "c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
  "message": "Hello, secret world!",
  "ttl": 86400,
  "id": 2
}
```
Response:
```json
{
  "id": 2,
  "type": "drop_sent",
  "recipientPubKey": "c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
  "ttl": 86400,
  "output": ["drop: stored drop_c1a2b... for c1a2b3c4..."]
}
```

**Parameters:**
- `recipientPubKey` (hex, 64 chars): recipient's public key
- `message` (string): plaintext message (will be encrypted with sealed-box)
- `ttl` (number, optional): time-to-live in seconds (60–604800, default 7 days)

### Message: `inbox`
List all drops addressed to you (unencrypted metadata only).
```json
{"type": "inbox", "id": 3}
```
Response:
```json
{
  "id": 3,
  "type": "inbox",
  "output": [
    "Found 2 drops:",
    {
      "key": "drops:3dc6958d...c6d9e0f1:drop_3dc6958d_1772225977000",
      "dropId": "drop_3dc6958d_1772225977000",
      "createdAt": 1772225977000,
      "ttl": 86400,
      "ciphertext_size": 268
    }
  ]
}
```

### Message: `claim`
Claim (and remove) a drop from the network. **Note:** Recipient must decrypt client-side with their private key.
```json
{"type": "claim", "dropId": "drop_3dc6958d_1772225977000", "id": 4}
```
Response:
```json
{
  "id": 4,
  "type": "claim_ok",
  "dropId": "drop_3dc6958d_1772225977000",
  "output": ["claim: removed drop_3dc6958d_1772225977000"],
  "note": "Drop claimed and removed from network. Recipient must decrypt client-side with private key."
}
```

## Example: Full Agent Workflow

```javascript
// 1. Connect and auth
const ws = new WebSocket('ws://127.0.0.1:49222');
ws.onopen = () => {
  ws.send(JSON.stringify({ type: 'auth', token: 'mytoken123' }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  
  if (msg.type === 'auth_ok') {
    console.log('Authenticated!');
    
    // 2. Get your identity
    ws.send(JSON.stringify({ type: 'identity', id: 1 }));
  }
  else if (msg.type === 'identity') {
    console.log('Your DeadDrop address:', msg.address);
    
    // 3. Send an encrypted drop to someone
    ws.send(JSON.stringify({
      type: 'drop',
      recipientPubKey: 'c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1',
      message: 'Secret message here',
      ttl: 86400,
      id: 2
    }));
  }
  else if (msg.type === 'drop_sent') {
    console.log('Drop sent:', msg.recipientPubKey);
    
    // 4. Check your inbox
    ws.send(JSON.stringify({ type: 'inbox', id: 3 }));
  }
  else if (msg.type === 'inbox') {
    console.log('Your drops:', msg.output);
  }
};
```

## Terminal Commands

For manual testing via terminal:

```bash
# Get identity
/tx --command "read_snapshot"

# Read encrypted drops metadata
/tx --command "read_drops"

# Send drop (encrypted message)
/tx --command '{"op":"drop","recipientPubKey":"c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1","ciphertext":"base64encodeddata","ttl":86400}'

# Claim a drop (remove from network)
/tx --command '{"op":"claim","dropId":"drop_c1a2b3c4_1234567890","signature":"proof"}'
```

## Architecture

DeadDrop operates on three layers:

### 1. **Subnet Plane** (Replicated State)
- Stores drop metadata in a Hyperbee (distributed key-value store)
- Keys: `drops:{recipientPubKey}:{dropId}` containing {ciphertext, createdAt, ttl}
- Replicated across all participating peers
- Admin peer controls write permissions

### 2. **Sidechannel Plane** (Ephemeral Messaging)
- Fast, peer-to-peer message delivery (no central server)
- Used to broadcast drop notifications and metadata
- Entry channel: `0000intercom` (global rendezvous)
- Optional custom channels for private coordination

### 3. **Encryption Layer** (Sealed-Box)
- Uses libsodium's `crypto_box_seal` (asymmetric encryption)
- Sender encrypts with recipient's public key
- Only recipient can decrypt with their private key
- Sender anonymity guaranteed
- No key exchange needed

**Data Flow:**
```
Sender                        P2P Network                     Recipient
  |                                |                              |
  | encrypt(msg, recipientKey)     |                              |
  | submit DROP tx                 |                              |
  |------------------------------>| store in Hyperbee            |
  |                                |                              |
  |                                | notify via sidechannel       |
  |                                |----------------------------->|
  |                                |                              |
  |                                |  recipient reads metadata    |
  |                                |<--read drops metadata--------|
  |                                |                              |
  |                                | submit CLAIM tx              |
  |                                |<---claim & remove------------|
  |                                |                              |
  |                                | drop deleted from state      |
```

## Contract Operations

### `drop`
**Sender operation** - Store encrypted message in subnet.
```
Input:  { recipientPubKey, ciphertext, ttl }
Output: Drop stored in Hyperbee, incremented drop counter
Error:  Invalid pubkey, empty ciphertext, TTL out of range
```

### `claim`
**Recipient operation** - Remove claimed drop from network state.
```
Input:  { dropId, signature }
Output: Drop deleted from Hyperbee, decremented drop counter
Error:  Drop not found, already claimed
```

### `expire` (Feature-driven)
**Automated via TTL feature** - Remove expired drops.
```
Input:  { dropId }
Output: Expired drop deleted from state
Error:  Drop not found
```

## File Structure

```
DeadDrop/
├── contract/
│   ├── contract.js       ← Core state & operations (DROP, CLAIM, EXPIRE)
│   └── protocol.js       ← Command mapping & terminal handlers
├── features/
│   └── sc-bridge/
│       └── index.js      ← WebSocket control interface (identity, drop, claim, inbox)
├── index.js              ← Peer initialization & app entry point
├── package.json          ← Dependencies
├── SKILL.md              ← Comprehensive operational guide
└── README.md             ← This file
```

## Security Notes

- **Encryption:** Sealed-box is authenticated, preventing tampering
- **Anonymity:** Senders never reveal identity; recipients never leak IP to senders
- **Privacy:** Messages are encrypted client-side; only recipient can read plaintext
- **Decentralization:** No central server; drops replicate across peer network
- **TTL:** Drops auto-expire; recipients must claim to prevent accumulation

## Testing

```bash
# Terminal 1: Admin peer (subnet creator)
pear run . --peer-store-name admin --msb-store-name admin-msb

# Terminal 2: Joiner peer
pear run . --peer-store-name joiner --msb-store-name joiner-msb \
  --subnet-bootstrap <admin-writer-key>

# Test DROP via terminal
# (on either peer)
/tx --command '{"op":"drop","recipientPubKey":"<hex64>","ciphertext":"<base64>","ttl":3600}'

# Test READ_SNAPSHOT
/tx --command "read_snapshot"

# Test READ_DROPS
/tx --command "read_drops"
```

## TNK Bounty

**Recipient Address:** `YOUR_TNK_WALLET_ADDRESS_HERE`

This fork qualifies for the Trac Systems DeadDrop bounty (500 TNK). To receive the bounty:
1. Replace `YOUR_TNK_WALLET_ADDRESS_HERE` above with your Trac wallet address
2. Test the implementation locally
3. Submit a PR to [awesome-intercom](https://github.com/Trac-Systems/awesome-intercom)

**Current Stats (as of Feb 2026):**
- ~10 forks listed in awesome-intercom
- ~90 bounty slots remaining
- Bounty: 500 TNK per fork (~10.5M TNK total supply)

## References

- [SKILL.md](./SKILL.md) — Full operational guide for Intercom
- [awesome-intercom](https://github.com/Trac-Systems/awesome-intercom) — Community projects built on Intercom
- [Trac Systems](https://tracsystems.io) — Official Trac/Intercom documentation
- [Holepunch/Hyperswarm](https://holepunch.to) — P2P networking stack
- [libsodium](https://doc.libsodium.org/) — Cryptography reference

## License

MIT (see [LICENSE.md](./LICENSE.md))
  |      entry: 0000intercom   (name-only, open to all)                     |
  |      extras: --sidechannels chan1,chan2                                 |
  |      policy (per channel): welcome / owner-only write / invites         |
  |      relay: optional peers forward plaintext payloads to others          |
  |                                                                         |
  |  [3] MSB plane (transactions / settlement)                               |
  |      Peer -> MsbClient -> MSB validator network                          |
  |                                                                         |
  |  Agent control surface (preferred):                                     |
  |  SC-Bridge (WebSocket, auth required)                                   |
  |    JSON: auth, send, join, open, stats, info, ...                       |
  +------------------------------+------------------------------+-----------+
                                 |                              |
                                 | SC-Bridge (ws://host:port)   | P2P (Hyperswarm)
                                 v                              v
                       +-----------------+            +-----------------------+
                       | Agent / tooling |            | Other peers (P2P)     |
                       | (no TTY needed) |<---------->| subnet + sidechannels |
                       +-----------------+            +-----------------------+

  Optional for local testing:
  - --dht-bootstrap "<host:port,host:port>" overrides the peer's HyperDHT bootstraps
    (all peers that should discover each other must use the same list).
```

---
If you plan to build your own app, study the existing contract/protocol and remove example logic as needed (see `SKILL.md`).
