import {Protocol} from "trac-peer";
import b4a from "b4a";
import PeerWallet from "trac-wallet";
import fs from "fs";

const stableStringify = (value) => {
    if (value === null || value === undefined) return 'null';
    if (typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) {
        return `[${value.map(stableStringify).join(',')}]`;
    }
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
};

const normalizeInvitePayload = (payload) => {
    return {
        channel: String(payload?.channel ?? ''),
        inviteePubKey: String(payload?.inviteePubKey ?? '').trim().toLowerCase(),
        inviterPubKey: String(payload?.inviterPubKey ?? '').trim().toLowerCase(),
        inviterAddress: payload?.inviterAddress ?? null,
        issuedAt: Number(payload?.issuedAt),
        expiresAt: Number(payload?.expiresAt),
        nonce: String(payload?.nonce ?? ''),
        version: Number.isFinite(payload?.version) ? Number(payload.version) : 1,
    };
};

const normalizeWelcomePayload = (payload) => {
    return {
        channel: String(payload?.channel ?? ''),
        ownerPubKey: String(payload?.ownerPubKey ?? '').trim().toLowerCase(),
        text: String(payload?.text ?? ''),
        issuedAt: Number(payload?.issuedAt),
        version: Number.isFinite(payload?.version) ? Number(payload.version) : 1,
    };
};

const parseInviteArg = (raw) => {
    if (!raw) return null;
    let text = String(raw || '').trim();
    if (!text) return null;
    if (text.startsWith('@')) {
        try {
            text = fs.readFileSync(text.slice(1), 'utf8').trim();
        } catch (_e) {
            return null;
        }
    }
    if (text.startsWith('b64:')) text = text.slice(4);
    if (text.startsWith('{')) {
        try {
            return JSON.parse(text);
        } catch (_e) {}
    }
    try {
        const decoded = b4a.toString(b4a.from(text, 'base64'));
        return JSON.parse(decoded);
    } catch (_e) {}
    return null;
};

const parseWelcomeArg = (raw) => {
    if (!raw) return null;
    let text = String(raw || '').trim();
    if (!text) return null;
    if (text.startsWith('@')) {
        try {
            text = fs.readFileSync(text.slice(1), 'utf8').trim();
        } catch (_e) {
            return null;
        }
    }
    if (text.startsWith('b64:')) text = text.slice(4);
    if (text.startsWith('{')) {
        try {
            return JSON.parse(text);
        } catch (_e) {}
    }
    try {
        const decoded = b4a.toString(b4a.from(text, 'base64'));
        return JSON.parse(decoded);
    } catch (_e) {}
    return null;
};

class DeadDropProtocol extends Protocol {
    /**
     * DeadDrop Protocol - Maps terminal/SC-Bridge commands to contract operations
     * 
     * Operations:
     * - drop: post an encrypted message to a recipient
     * - claim: decrypt and retrieve a drop
     * - expire: auto-expire old drops (called by TTL feature)
     * - read_drops: list drops for a recipient (read-only)
     */

    mapTxCommand(command) {
        const obj = { type: null, value: null };

        // Single-word commands (no parameters)
        if (command === 'read_snapshot') {
            obj.type = 'readSnapshot';
            obj.value = null;
            return obj;
        } else if (command === 'read_drops') {
            obj.type = 'readDrops';
            obj.value = null;
            return obj;
        } else if (command === 'read_timer') {
            obj.type = 'readTimer';
            obj.value = null;
            return obj;
        } else {
            // JSON-based commands for structured payloads
            const json = this.safeJsonParse(command);
            if (!json || typeof json !== 'object') return null;

            // DROP: { "op": "drop", "recipientPubKey": "...", "ciphertext": "...", "ttl": 86400 }
            if (json.op === 'drop') {
                obj.type = 'drop';
                obj.value = json;
                return obj;
            }

            // CLAIM: { "op": "claim", "dropId": "...", "signature": "..." }
            if (json.op === 'claim') {
                obj.type = 'claim';
                obj.value = json;
                return obj;
            }

            // EXPIRE: { "op": "expire", "dropId": "..." }
            // Called by TTL feature to remove expired drops
            if (json.op === 'expire') {
                obj.type = 'expire';
                obj.value = json;
                return obj;
            }

            // READ_KEY: read arbitrary state key
            if (json.op === 'read_key') {
                obj.type = 'readKey';
                obj.value = json;
                return obj;
            }
        }

        return null;
    }

    async printOptions() {
        console.log(' ');
        console.log('- DeadDrop Commands:');
        console.log('- /tx --command "{\"op\": \"drop\", \"recipientPubKey\": \"<hex>\", \"ciphertext\": \"<base64>\", \"ttl\": 86400}" | Send encrypted drop');
        console.log('- /tx --command "{\"op\": \"claim\", \"dropId\": \"<id>\", \"signature\": \"<hex>\"}" | Claim and decrypt a drop');
        console.log('- /tx --command "{\"op\": \"read_key\", \"key\": \"drops:<recipient>:<id>\"}" | Read drop metadata');
        console.log('- /tx --command "read_drops" | List all drops addressed to you');
        console.log('- /tx --command "read_snapshot" | Read contract snapshot');
        console.log('- /tx --command "read_timer" | Read current timer value');
        console.log('- /get --key "drops:<recipient>:<id>" | Read unsigned drop data');
        console.log('- /sc_join --channel "<name>" | Join ephemeral sidechannel');
        console.log('- /sc_send --channel "<name>" --message "<text>" | Send sidechannel message');
        console.log('- /sc_stats | Show sidechannel connection stats');
    }

    async customCommand(input) {
        await super.tokenizeInput(input);
        if (this.input.startsWith("/get")) {
            const m = input.match(/(?:^|\s)--key(?:=|\s+)(\"[^\"]+\"|'[^']+'|\S+)/);
            const raw = m ? m[1].trim() : null;
            if (!raw) {
                console.log('Usage: /get --key "<hyperbee-key>" [--confirmed true|false] [--unconfirmed 1]');
                return;
            }
            const key = raw.replace(/^\"(.*)\"$/, "$1").replace(/^'(.*)'$/, "$1");
            const confirmedMatch = input.match(/(?:^|\s)--confirmed(?:=|\s+)(\S+)/);
            const unconfirmedMatch = input.match(/(?:^|\s)--unconfirmed(?:=|\s+)?(\S+)?/);
            const confirmed = unconfirmedMatch ? false : confirmedMatch ? confirmedMatch[1] === "true" || confirmedMatch[1] === "1" : true;
            const v = confirmed ? await this.getSigned(key) : await this.get(key);
            console.log(v);
            return;
        }
        if (this.input.startsWith("/sc_join")) {
            const args = this.parseArgs(input);
            const name = args.channel || args.ch || args.name;
            if (!name) {
                console.log('Usage: /sc_join --channel "<name>"');
                return;
            }
            if (!this.peer.sidechannel) {
                console.log('Sidechannel not initialized.');
                return;
            }
            const ok = await this.peer.sidechannel.addChannel(String(name));
            if (!ok) {
                console.log('Join denied (invite required or invalid).');
                return;
            }
            console.log('Joined sidechannel:', name);
            return;
        }
        if (this.input.startsWith("/sc_send")) {
            const args = this.parseArgs(input);
            const name = args.channel || args.ch || args.name;
            const message = args.message || args.msg;
            if (!name || message === undefined) {
                console.log('Usage: /sc_send --channel "<name>" --message "<text>"');
                return;
            }
            if (!this.peer.sidechannel) {
                console.log('Sidechannel not initialized.');
                return;
            }
            const sent = this.peer.sidechannel.broadcast(String(name), message);
            if (!sent) {
                console.log('Send denied.');
            }
            return;
        }
        if (this.input.startsWith("/sc_stats")) {
            if (!this.peer.sidechannel) {
                console.log('Sidechannel not initialized.');
                return;
            }
            const channels = Array.from(this.peer.sidechannel.channels.keys());
            const connectionCount = this.peer.sidechannel.connections.size;
            console.log({ channels, connectionCount });
            return;
        }
    }
}

export default DeadDropProtocol;
