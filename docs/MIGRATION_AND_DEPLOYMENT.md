# Migration and deployment

How Q-Uplink moves a mission from today's cryptography to post-quantum signatures,
and what it takes to run it on a real spacecraft and ground segment. Everything in
sections 1 to 4 is implemented and tested (`tests/test_keys.py`, the key-management
drill in `scripts/final_run.py`); section 5 lists what a flight programme would add.

## 1. Crypto agility: the algorithm belongs to the key

Every onboard public key is provisioned with exactly one signature suite. When a
frame arrives, the satellite takes the algorithm from the key named by `key_id`,
never from a field the sender controls, so an attacker cannot relabel a frame to a
weaker algorithm (test: `test_algorithm_is_bound_to_the_key_no_downgrade`).
The frame header is unchanged; only the signature length follows the key's suite.

| Suite | Signature | Frame (12 B command) | Fits one CCSDS TC frame (1,024 B) | Status |
|---|---|---|---|---|
| Falcon-padded-512 (default) | 666 B | 694 B | Yes | NIST-selected; FN-DSA (FIPS 206) in draft |
| Hybrid Ed25519 + Falcon-512 | 730 B | 758 B | Yes | Secure while either algorithm holds |
| ML-DSA-44 | 2,420 B | 2,448 B | No (needs segmentation) | FIPS 204, final |

Moving to another algorithm is therefore a key rotation: no new frame format, no
new parser, no flag day.

## 2. The pre-loaded key ring

Eight public keys are provisioned before launch (about 8 KB of onboard storage):

| key_id | Role | Suite | Starts as | Purpose |
|---|---|---|---|---|
| 1 / 2 | OPERATOR / ADMIN | Falcon-512 | active | Primary keys |
| 3 / 4 | OPERATOR / ADMIN | Falcon-512 | standby | Routine rotation and compromise response |
| 5 / 6 | OPERATOR / ADMIN | ML-DSA-44 | standby | Fallback to the final NIST standard |
| 7 / 8 | OPERATOR / ADMIN | Hybrid Ed25519 + Falcon-512 | standby | Transition suite |

Two ADMIN-only commands manage it:

- `KEY_ACTIVATE(key_id)`: a standby key becomes active.
- `KEY_REVOKE(key_id)`: a key is revoked for good.

The satellite enforces a policy before accepting either one (`E_KEY_POLICY`):
- only standby keys can be activated;
- a revoked key can never return;
- the last active ADMIN key can't be revoked, so the spacecraft can't lock itself out.

Each command is an ordinary signed, counted frame. Its state change happens in the same single non-volatile write as the counter.

Frames signed with a revoked key are refused as `E_KEY_REVOKED`, and frames signed with a standby key as `E_KEY_INACTIVE`. Both checks happen before any signature work, so a stolen key can't even make the satellite spend CPU.

**Rotation in practice (Attack lab → Key management, or `POST /api/keys/rotate`):**
1. ADMIN sends `KEY_ACTIVATE(new)`. After the acknowledgement, the ground signs with the new key. Old and new keys overlap for one frame.
2. ADMIN sends `KEY_REVOKE(old)`. An ADMIN key signs its own revocation, so the frame stays small even when migrating to ML-DSA.
3. The ground marks the old private key as retired and refuses to sign with it. In production it would be destroyed.
4. Planning is re-sized automatically: QpiAI Opt plans are sized from each role's current signature length. A plan made before a migration then fails its pre-signing check until it is re-optimised.

Compromise response takes two frames, about 1.4 KB, so it fits inside a single pass.

## 3. Migration path for a mission

| Phase | Onboard keys used | What it protects against | Cost per command frame |
|---|---|---|---|
| 0. Legacy | Classical only (for example ECDSA, or symmetric MACs as in CCSDS SDLS) | Today's attackers | 64 B signature, or a 16 B MAC |
| 1. Hybrid | Activate keys 7/8, revoke the classical keys | Quantum attacks, plus a flaw in either one algorithm | 758 B |
| 2. Post-quantum | Activate Falcon keys, revoke hybrid | Quantum attacks; smallest PQ frames | 694 B |
| Fallback | Activate ML-DSA-44 keys (FIPS 204) if Falcon or its implementation is ever in doubt | Same, with a final standard | 2,448 B: 1 command per 3,600 B pass instead of 4 |
| Standards update | When FIPS 206 (FN-DSA) is final, provision FN-DSA keys at the next key load and rotate | Standards compliance | About the same as Falcon |

Our demo satellite starts at phase 2 and carries phase 1 and the fallback as standby keys. A legacy satellite moves through the phases by the same rotation commands, once its key ring is loaded.

Public-key signatures add something over shared-secret MACs: the satellite stores only public keys. Reading its memory therefore never yields the ability to command it, or any other satellite.

## 4. Keys at rest on the ground

With `QUPLINK_KEY_PASSPHRASE` set in `.env`, every private key is stored sealed:
- the key is scrypt-derived (n = 2^15, r = 8, p = 1, random salt);
- it is encrypted with AES-256-GCM, with the key id as associated data;
- plaintext key files from earlier runs are sealed and then removed at start-up.

Without a passphrase the app runs, but the Attack lab and the final run say that keys are in plaintext. The public evidence bundle contains public keys only.

## 5. Deploying on a real mission

**Spacecraft:**
- The satellite only verifies. Falcon verification uses integer arithmetic only (no floating point), and PQClean's implementation is portable C, so it suits an on-board computer without an FPU. Signing, which does use floating point, stays on the ground.
- Measured on the team laptop (Python, emulated host):
  - Falcon verify p50: 73–76 µs.
  - Peak memory per verification: about 22 KB.
  - Non-volatile writes: exactly one per accepted command, none per rejected one.
- Onboard state needs about 8 KB for the key ring, plus the counter, the pass nonce and the key states.

**Link:**
- The frame maps onto CCSDS Space Data Link Security concepts:
  - `key_id` corresponds to the Security Parameter Index (which security association or key);
  - the counter corresponds to the anti-replay sequence number;
  - the signature takes the place of the MAC in the security trailer.
- The pass nonce has no SDLS field: it is bound into the signed data and never transmitted with ordinary frames.
- A Falcon or hybrid frame (at most 779 B, a hybrid PASS_OPEN) fits a single 1,024-octet TC transfer frame. ML-DSA frames would need TC segmentation, one more reason Falcon is the default.

**Ground segment:**
- Keys belong in an HSM, with OPERATOR and ADMIN keys in separate partitions (for example, a two-person rule for ADMIN). The sealed key files are the prototype's stand-in.
- The ground service is a single Python process (FastAPI) with the satellite emulator as a second process.
- QpiAI Opt runs locally with the team's API key, at no credit cost.
- For multi-operator use, put it behind an authenticating reverse proxy. The prototype binds to 127.0.0.1 only.

**Not covered by the prototype:**
- loading new public keys onto a satellite already in orbit (a chunked, ADMIN-signed key upload);
- HSM integration;
- side-channel hardening of the onboard verifier;
- a flight-qualified C build;
- authentication of the downlink (ACKs and telemetry).
