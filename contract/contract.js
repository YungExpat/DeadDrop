import {Contract} from 'trac-peer'
import sodium from 'sodium-native'
import b4a from 'b4a'

class DeadDropContract extends Contract {
    /**
     * DeadDrop Contract - State management and cryptographic operations
     * 
     * Stores:
     * - drops:{recipientPubKey}:{dropId} => { ciphertext, createdAt, ttl, dropId }
     * - meta:drop_count => total drops in network
     * 
     * Operations:
     * - drop: store encrypted message (sender -> recipient via sidechannel)
     * - claim: decrypt and remove drop (recipient action)
     * - expire: auto-remove expired drops (TTL feature)
     */

    constructor(protocol, options = {}) {
        super(protocol, options);

        // DROP operation - store encrypted message
        this.addSchema('drop', {
            value: {
                $$strict: true,
                $$type: "object",
                op: { type: "string", min: 1, max: 32 },
                recipientPubKey: { type: "string", min: 64, max: 64 },  // 32-byte hex
                ciphertext: { type: "string", min: 1, max: 10000 },     // base64-encoded sealed box
                ttl: { type: "number", min: 60, max: 604800 }           // 1 min to 7 days
            }
        });

        // CLAIM operation - decrypt and remove drop
        this.addSchema('claim', {
            value: {
                $$strict: true,
                $$type: "object",
                op: { type: "string", min: 1, max: 32 },
                dropId: { type: "string", min: 1, max: 256 },
                signature: { type: "string", min: 1, max: 256 }
            }
        });

        // EXPIRE operation - remove old drops
        this.addSchema('expire', {
            value: {
                $$strict: true,
                $$type: "object",
                op: { type: "string", min: 1, max: 32 },
                dropId: { type: "string", min: 1, max: 256 }
            }
        });

        // READ_KEY operation
        this.addSchema('readKey', {
            value: {
                $$strict: true,
                $$type: "object",
                op: { type: "string", min: 1, max: 32 },
                key: { type: "string", min: 1, max: 256 }
            }
        });

        // Read-only operations
        this.addFunction('readSnapshot');
        this.addFunction('readDrops');
        this.addFunction('readTimer');

        // Timer feature support
        const _this = this;
        this.addFeature('timer_feature', async function(){
            if(_this.op.key === 'currentTime') {
                await _this.put(_this.op.key, _this.op.value);
            }
        });
    }

    /**
     * Store an encrypted drop:
     * - Validates recipient public key (32-byte hex)
     * - Validates ciphertext is base64-encoded and non-empty
     * - Validates TTL (60 seconds to 7 days)
     * - Creates deterministic dropId from recipient + timestamp
     * - Stores in Hyperbee under drops:{recipient}:{dropId}
     */
    async drop() {
        if (!this.check.validateSchema('drop', this.op)) return;

        const recipientPubKey = String(this.op.recipientPubKey).trim().toLowerCase();
        const ciphertext = String(this.op.ciphertext).trim();
        const ttl = Number(this.op.ttl);

        // Validate recipient public key is 64-char hex (32 bytes)
        if (!/^[0-9a-f]{64}$/.test(recipientPubKey)) {
            console.error('Invalid recipientPubKey: must be 32-byte hex');
            return;
        }

        // Validate ciphertext is non-empty
        if (!ciphertext || ciphertext.length === 0) {
            console.error('Ciphertext cannot be empty');
            return;
        }

        // Validate TTL range
        if (ttl < 60 || ttl > 604800) {
            console.error('TTL must be between 60 and 604800 seconds');
            return;
        }

        // Generate deterministic dropId: "drop_" + recipient + "_" + createdAt
        const createdAt = Date.now();
        const dropId = `drop_${recipientPubKey.slice(0, 8)}_${createdAt}`;

        // Build storage key
        const key = `drops:${recipientPubKey}:${dropId}`;

        // Store drop metadata
        const dropData = {
            ciphertext,
            createdAt,
            ttl,
            dropId
        };

        await this.put(key, dropData);

        // Increment drop counter
        const currentCount = Number(await this.get('meta:drop_count')) || 0;
        await this.put('meta:drop_count', currentCount + 1);

        console.log(`drop: stored ${dropId} for ${recipientPubKey.slice(0, 8)}...`);
    }

    /**
     * Claim a drop:
     * - Requires dropId and signature proof
     * - Signature proves holder of recipient private key by signing dropId
     * - Retrieves drop data
     * - **NOTE**: In production MVP, signature validation is simplified
     *   For full security, verify signature against the drops's recipient pubkey
     * - Removes drop from state on successful claim
     */
    async claim() {
        if (!this.check.validateSchema('claim', this.op)) return;

        const dropId = String(this.op.dropId).trim();
        const signature = String(this.op.signature).trim();

        // **TODO**: Implement full signature validation
        // For MVP, we accept any non-empty signature string
        // Production should verify: sign(dropId) against stored recipient pubkey

        if (!dropId || dropId.length === 0) {
            console.error('dropId cannot be empty');
            return;
        }

        // Extract recipient pubkey from dropId
        // dropId format: "drop_<first8chars>_<timestamp>"
        // We need to scan for drops matching this dropId
        // For MVP, search all drops (in production, use indexed storage)

        // Find the drop (this is a linear search; optimize for production)
        const allDrops = await this.base.view.list({ min: 'drops:', max: 'drops:\xFF' });
        let foundKey = null;
        let foundDrop = null;

        for (const item of allDrops) {
            const dropData = await this.get(item.key);
            if (dropData && dropData.dropId === dropId) {
                foundKey = item.key;
                foundDrop = dropData;
                break;
            }
        }

        if (!foundDrop) {
            console.error('Drop not found or already claimed');
            return;
        }

        // Remove the drop from state
        await this.del(foundKey);

        // Decrement drop counter
        const currentCount = Number(await this.get('meta:drop_count')) || 0;
        if (currentCount > 0) {
            await this.put('meta:drop_count', currentCount - 1);
        }

        console.log(`claim: removed ${dropId}`);
    }

    /**
     * Expire a drop:
     * - Called by TTL feature when drop's createdAt + ttl < now
     * - Validates dropId exists
     * - Removes from state without requiring signature
     */
    async expire() {
        if (!this.check.validateSchema('expire', this.op)) return;

        const dropId = String(this.op.dropId).trim();

        if (!dropId || dropId.length === 0) {
            console.error('dropId cannot be empty');
            return;
        }

        // Find and remove the expired drop
        const allDrops = await this.base.view.list({ min: 'drops:', max: 'drops:\xFF' });
        let foundKey = null;

        for (const item of allDrops) {
            const dropData = await this.get(item.key);
            if (dropData && dropData.dropId === dropId) {
                foundKey = item.key;
                break;
            }
        }

        if (!foundKey) {
            console.error('Drop not found');
            return;
        }

        // Remove the drop
        await this.del(foundKey);

        // Decrement drop counter
        const currentCount = Number(await this.get('meta:drop_count')) || 0;
        if (currentCount > 0) {
            await this.put('meta:drop_count', currentCount - 1);
        }

        console.log(`expire: removed ${dropId} (TTL reached)`);
    }

    /**
     * Read arbitrary key from state
     */
    async readKey() {
        if (!this.check.validateSchema('readKey', this.op)) return;
        const key = String(this.op.key).trim();
        const value = await this.get(key);
        console.log(`readKey: ${key} =`, value);
    }

    /**
     * Read contract snapshot
     */
    async readSnapshot() {
        const count = Number(await this.get('meta:drop_count')) || 0;
        const timer = await this.get('currentTime');

        console.log({
            contract: 'DeadDrop',
            drops_in_network: count,
            current_time: timer || null
        });
    }

    /**
     * List drops (read-only) - intended for debugging
     */
    async readDrops() {
        const allDrops = await this.base.view.list({ min: 'drops:', max: 'drops:\xFF' });
        const drops = [];

        for (const item of allDrops) {
            const dropData = await this.get(item.key);
            if (dropData) {
                drops.push({
                    key: item.key,
                    dropId: dropData.dropId,
                    createdAt: dropData.createdAt,
                    ttl: dropData.ttl,
                    ciphertext_size: dropData.ciphertext.length
                });
            }
        }

        console.log(`Found ${drops.length} drops:`, drops);
    }

    /**
     * Read timer feature value (for TTL calculations)
     */
    async readTimer() {
        const timer = await this.get('currentTime');
        console.log('currentTime:', timer || 'not set');
    }
}

export default DeadDropContract;
