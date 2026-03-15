/// UltrafastSecp256k1 -- Rust Example
///
/// Demonstrates the safe Rust wrapper: key ops, ECDSA, Schnorr, ECDH,
/// hashing, Bitcoin addresses, BIP-32, and Taproot.
///
/// Build & Run:
///   UFSECP_LIB_DIR=../../build-linux/include/ufsecp \
///   LD_LIBRARY_PATH=../../build-linux/include/ufsecp \
///   cargo run
use ufsecp::{Context, Network};

fn hexs(data: &[u8]) -> String {
    hex::encode(data)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("UltrafastSecp256k1 -- Rust Example");
    println!("ABI version: {}", Context::abi_version());
    println!("Library:     {}", Context::version_string());
    println!();

    let ctx = Context::new()?;

    let privkey: [u8; 32] = {
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    };
    let privkey2: [u8; 32] = {
        let mut k = [0u8; 32];
        k[31] = 2;
        k
    };

    // ── 1. Key Generation ────────────────────────────────────────────
    println!("[1] Key Generation");
    let pub33 = ctx.pubkey_create(&privkey)?;
    let pub65 = ctx.pubkey_create_uncompressed(&privkey)?;
    let xonly = ctx.pubkey_xonly(&privkey)?;

    println!("  Private key:        {}", hexs(&privkey));
    println!("  Compressed (33B):   {}", hexs(&pub33));
    println!("  Uncompressed (65B): {}", hexs(&pub65));
    println!("  X-only (32B):       {}", hexs(&xonly));
    println!();

    // ── 2. ECDSA ─────────────────────────────────────────────────────
    println!("[2] ECDSA Sign / Verify (RFC 6979)");
    let msg = Context::sha256(b"Hello UltrafastSecp256k1!")?;
    println!("  Message hash:       {}", hexs(&msg));

    let sig = ctx.ecdsa_sign(&msg, &privkey)?;
    println!("  ECDSA signature:    {}", hexs(&sig));

    let valid = ctx.ecdsa_verify(&msg, &sig, &pub33);
    println!("  Verify:             {}", if valid { "VALID" } else { "INVALID" });

    // DER encoding
    let der = ctx.ecdsa_sig_to_der(&sig)?;
    println!("  DER length:         {} bytes", der.len());
    let sig_back = ctx.ecdsa_sig_from_der(&der)?;
    println!("  DER roundtrip:      {}", if sig == sig_back { "match" } else { "MISMATCH" });

    // Recovery
    let rsig = ctx.ecdsa_sign_recoverable(&msg, &privkey)?;
    let recovered = ctx.ecdsa_recover(&msg, &rsig.signature, rsig.recovery_id)?;
    println!("  Recovery:           recid={}, match={}", rsig.recovery_id,
             if recovered == pub33 { "YES" } else { "NO" });
    println!();

    // ── 3. Schnorr ───────────────────────────────────────────────────
    println!("[3] Schnorr Sign / Verify (BIP-340)");
    let aux = [0u8; 32];
    let schnorr_sig = ctx.schnorr_sign(&msg, &privkey, &aux)?;
    println!("  Schnorr signature:  {}", hexs(&schnorr_sig));

    let valid = ctx.schnorr_verify(&msg, &schnorr_sig, &xonly);
    println!("  Verify:             {}", if valid { "VALID" } else { "INVALID" });
    println!();

    // ── 4. ECDH ──────────────────────────────────────────────────────
    println!("[4] ECDH Key Agreement");
    let pub2 = ctx.pubkey_create(&privkey2)?;
    let secret_a = ctx.ecdh(&privkey, &pub2)?;
    let secret_b = ctx.ecdh(&privkey2, &pub33)?;
    println!("  Secret (A->B):      {}", hexs(&secret_a));
    println!("  Secret (B->A):      {}", hexs(&secret_b));
    println!("  Match:              {}", if secret_a == secret_b { "YES" } else { "NO" });
    println!();

    // ── 5. Hashing ───────────────────────────────────────────────────
    println!("[5] Hashing");
    let sha = Context::sha256(&pub33)?;
    let h160 = Context::hash160(&pub33)?;
    let tagged = Context::tagged_hash("BIP0340/challenge", &msg)?;
    println!("  SHA-256(pubkey):    {}", hexs(&sha));
    println!("  Hash160(pubkey):    {}", hexs(&h160));
    println!("  Tagged hash:        {}", hexs(&tagged));
    println!();

    // ── 6. Bitcoin Addresses ─────────────────────────────────────────
    println!("[6] Bitcoin Addresses");
    println!("  P2PKH:              {}", ctx.addr_p2pkh(&pub33, Network::Mainnet)?);
    println!("  P2WPKH:             {}", ctx.addr_p2wpkh(&pub33, Network::Mainnet)?);
    println!("  P2TR:               {}", ctx.addr_p2tr(&xonly, Network::Mainnet)?);
    println!();

    // ── 7. WIF ───────────────────────────────────────────────────────
    println!("[7] WIF Encoding");
    let wif = ctx.wif_encode(&privkey, true, Network::Mainnet)?;
    println!("  WIF:                {}", wif);
    let decoded = ctx.wif_decode(&wif)?;
    println!("  Decode roundtrip:   match={}", if decoded.privkey == privkey { "YES" } else { "NO" });
    println!();

    // ── 8. BIP-32 ────────────────────────────────────────────────────
    println!("[8] BIP-32 HD Key Derivation");
    let seed = [0x42u8; 64];
    let master = ctx.bip32_master(&seed)?;
    let child_key = ctx.bip32_derive_path(&master, "m/44'/0'/0'/0/0")?;
    let child_priv = ctx.bip32_privkey(&child_key)?;
    let child_pub = ctx.bip32_pubkey(&child_key)?;
    println!("  BIP-32 child priv:  {}", hexs(&child_priv));
    println!("  BIP-32 child pub:   {}", hexs(&child_pub));
    println!();

    // ── 9. Taproot ───────────────────────────────────────────────────
    println!("[9] Taproot (BIP-341)");
    let tap = ctx.taproot_output_key(&xonly, None)?;
    println!("  Output key:         {}", hexs(&tap.output_key_x));
    println!("  Parity:             {}", tap.parity);
    let valid = ctx.taproot_verify(&tap.output_key_x, tap.parity, &xonly, None);
    println!("  Verify:             {}", if valid { "VALID" } else { "INVALID" });
    println!();

    println!("All examples completed successfully.");
    Ok(())
}
