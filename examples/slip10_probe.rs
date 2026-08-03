//! Live-HSM SLIP-10 validation probe (Securosys Primus / CloudHSM).
//!
//! Proves the real derivation + signing flow against the HSM before it goes into
//! `SecurosysBackend`:
//!   master keygen (`CKM_EC_SLIP10_KEY_PAIR_GEN`) → whole-path child derive
//!   (`CKM_SLIP10_CHILD_DERIVE` via the vendor `C_DeriveKeyPair`) → read EC point
//!   + chain code → ECDSA sign → host-side secp256k1 verify.
//!
//! Uses raw PKCS#11 FFI (`cryptoki-sys` types + `libloading`) because the vendor
//! key type / attributes / `C_DeriveKeyPair` aren't expressible via cryptoki's
//! typed API. Ephemeral session objects only (nothing persisted).
//!
//! Run:
//!   SECUROSYS_PKCS11_LIB=/usr/lib/libprimusP11.so \
//!   SECUROSYS_SLOT_LABEL=YHRXBOTJLQWT \
//!   SECUROSYS_PKCS11_PASSWORD=... \
//!   cargo run --example slip10_probe

#![allow(non_snake_case, non_upper_case_globals, clippy::too_many_lines)]

use std::os::raw::c_void;
use std::ptr;

use cryptoki_sys::*;

// --- Vendor constants (from /usr/local/primus/include/pkcs11.h) ---
const CKM_EC_SLIP10_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x8000_0E02;
const CKM_SLIP10_CHILD_DERIVE: CK_MECHANISM_TYPE = 0x8000_0E01;
const CKK_EC_SLIP10: CK_KEY_TYPE = 0x8000_0014;
const CKA_SLIP10_CHAIN_CODE: CK_ATTRIBUTE_TYPE = 0x8000_1100;

// secp256k1 curve OID (DER): 1.3.132.0.10
const SECP256K1_OID: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];

#[repr(C)]
struct CkSlip10ChildDeriveParams {
    pul_path_indexes: *const CK_ULONG,
    ul_index_count: CK_ULONG,
}

// Vendor extension: derives a child *pair* from a parent private key.
type CDeriveKeyPairFn = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, // base (parent) key
    CK_ATTRIBUTE_PTR,
    CK_ULONG, // pub template
    CK_ATTRIBUTE_PTR,
    CK_ULONG, // priv template
    CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR, // out pub, priv
) -> CK_RV;

macro_rules! ck {
    ($e:expr, $what:expr) => {{
        let rv = $e;
        if rv != CKR_OK {
            return Err(format!("{} failed: rv=0x{:x}", $what, rv));
        }
    }};
}

fn attr(t: CK_ATTRIBUTE_TYPE, p: *mut c_void, len: usize) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: t,
        pValue: p,
        ulValueLen: len as CK_ULONG,
    }
}

fn main() {
    match run() {
        Ok(()) => println!(
            "\n✅ SLIP-10 probe PASSED — master gen + whole-path derive + sign + verify all green."
        ),
        Err(e) => {
            eprintln!("\n❌ SLIP-10 probe FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let lib_path =
        std::env::var("SECUROSYS_PKCS11_LIB").unwrap_or_else(|_| "/usr/lib/libprimusP11.so".into());
    let slot_label = std::env::var("SECUROSYS_SLOT_LABEL").unwrap_or_default();
    let pin = std::env::var("SECUROSYS_PKCS11_PASSWORD")
        .map_err(|_| "SECUROSYS_PKCS11_PASSWORD not set".to_string())?;

    // Load the provider + resolve the standard function list + the vendor fn.
    let lib = unsafe { libloading::Library::new(&lib_path) }
        .map_err(|e| format!("dlopen {lib_path}: {e}"))?;

    let fl: CK_FUNCTION_LIST_PTR = unsafe {
        let get_list: libloading::Symbol<unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> =
            lib.get(b"C_GetFunctionList")
                .map_err(|e| format!("C_GetFunctionList symbol: {e}"))?;
        let mut list: CK_FUNCTION_LIST_PTR = ptr::null_mut();
        let rv = get_list(&mut list);
        if rv != CKR_OK {
            return Err(format!("C_GetFunctionList rv=0x{rv:x}"));
        }
        list
    };
    macro_rules! f {
        ($name:ident) => {
            unsafe {
                (*fl)
                    .$name
                    .ok_or(concat!(stringify!($name), " null in fn list"))?
            }
        };
    }

    let derive_key_pair: libloading::Symbol<CDeriveKeyPairFn> = unsafe {
        lib.get(b"C_DeriveKeyPair")
            .map_err(|e| format!("C_DeriveKeyPair symbol: {e}"))?
    };

    unsafe {
        ck!(f!(C_Initialize)(ptr::null_mut()), "C_Initialize");

        // Find the slot whose token label matches, else first slot.
        let mut count: CK_ULONG = 0;
        ck!(
            f!(C_GetSlotList)(CK_TRUE, ptr::null_mut(), &mut count),
            "C_GetSlotList(count)"
        );
        let mut slots = vec![0 as CK_SLOT_ID; count as usize];
        ck!(
            f!(C_GetSlotList)(CK_TRUE, slots.as_mut_ptr(), &mut count),
            "C_GetSlotList"
        );
        let mut chosen: Option<CK_SLOT_ID> = None;
        for &s in &slots {
            let mut ti: CK_TOKEN_INFO = std::mem::zeroed();
            if f!(C_GetTokenInfo)(s, &mut ti) == CKR_OK {
                let label = String::from_utf8_lossy(&ti.label).trim().to_string();
                println!("slot {s}: token label '{label}'");
                if slot_label.is_empty() || label == slot_label {
                    chosen = Some(s);
                    break;
                }
            }
        }
        let slot = chosen.ok_or("no matching slot")?;
        println!("using slot {slot}");

        let mut session: CK_SESSION_HANDLE = 0;
        ck!(
            f!(C_OpenSession)(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut session
            ),
            "C_OpenSession"
        );
        ck!(
            f!(C_Login)(
                session,
                CKU_USER,
                pin.as_ptr() as *mut u8,
                pin.len() as CK_ULONG
            ),
            "C_Login"
        );
        println!("logged in.");

        // ---- Master key pair from a 32-byte seed ----
        let seed = [0x41u8; 32];
        let mut mech = CK_MECHANISM {
            mechanism: CKM_EC_SLIP10_KEY_PAIR_GEN,
            pParameter: seed.as_ptr() as *mut c_void,
            ulParameterLen: seed.len() as CK_ULONG,
        };
        let (mut ck_true, mut ck_false) = (CK_TRUE, CK_FALSE);
        let mut cls_pub: CK_OBJECT_CLASS = CKO_PUBLIC_KEY;
        let mut cls_priv: CK_OBJECT_CLASS = CKO_PRIVATE_KEY;
        let mut kt: CK_KEY_TYPE = CKK_EC_SLIP10;
        let mut oid = SECP256K1_OID;

        let pv = |p: &mut CK_BBOOL| p as *mut _ as *mut c_void;
        let mut pub_tmpl = [
            attr(
                CKA_CLASS,
                &mut cls_pub as *mut _ as *mut c_void,
                std::mem::size_of::<CK_OBJECT_CLASS>(),
            ),
            attr(
                CKA_KEY_TYPE,
                &mut kt as *mut _ as *mut c_void,
                std::mem::size_of::<CK_KEY_TYPE>(),
            ),
            attr(CKA_TOKEN, pv(&mut ck_false), 1),
            attr(CKA_DERIVE, pv(&mut ck_true), 1),
            attr(CKA_VERIFY, pv(&mut ck_true), 1),
            attr(CKA_EC_PARAMS, oid.as_mut_ptr() as *mut c_void, oid.len()),
        ];
        let mut priv_tmpl = [
            attr(
                CKA_CLASS,
                &mut cls_priv as *mut _ as *mut c_void,
                std::mem::size_of::<CK_OBJECT_CLASS>(),
            ),
            attr(
                CKA_KEY_TYPE,
                &mut kt as *mut _ as *mut c_void,
                std::mem::size_of::<CK_KEY_TYPE>(),
            ),
            attr(CKA_TOKEN, pv(&mut ck_false), 1),
            attr(CKA_DERIVE, pv(&mut ck_true), 1),
            attr(CKA_SIGN, pv(&mut ck_true), 1),
            attr(CKA_SENSITIVE, pv(&mut ck_true), 1),
            attr(CKA_EXTRACTABLE, pv(&mut ck_false), 1),
        ];
        let (mut m_pub, mut m_priv): (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) = (0, 0);
        ck!(
            f!(C_GenerateKeyPair)(
                session,
                &mut mech,
                pub_tmpl.as_mut_ptr(),
                pub_tmpl.len() as CK_ULONG,
                priv_tmpl.as_mut_ptr(),
                priv_tmpl.len() as CK_ULONG,
                &mut m_pub,
                &mut m_priv,
            ),
            "C_GenerateKeyPair(master)"
        );
        println!("master keypair: pub={m_pub} priv={m_priv}");
        let mcc = read_var(fl, session, m_priv, CKA_SLIP10_CHAIN_CODE)?;
        println!("master chain code: {}", hex::encode(&mcc));

        // ---- Whole-path child derive: m/44'/0'/0'/0/1 ----
        let path: [CK_ULONG; 5] = [0x8000_002C, 0x8000_0000, 0x8000_0000, 0, 1];
        let params = CkSlip10ChildDeriveParams {
            pul_path_indexes: path.as_ptr(),
            ul_index_count: path.len() as CK_ULONG,
        };
        let mut dmech = CK_MECHANISM {
            mechanism: CKM_SLIP10_CHILD_DERIVE,
            pParameter: &params as *const _ as *mut c_void,
            ulParameterLen: std::mem::size_of::<CkSlip10ChildDeriveParams>() as CK_ULONG,
        };
        let mut cpub_tmpl = [
            attr(CKA_TOKEN, pv(&mut ck_false), 1),
            attr(CKA_DERIVE, pv(&mut ck_false), 1),
            attr(CKA_VERIFY, pv(&mut ck_true), 1),
        ];
        let mut cpriv_tmpl = [
            attr(CKA_TOKEN, pv(&mut ck_false), 1),
            attr(CKA_DERIVE, pv(&mut ck_false), 1),
            attr(CKA_SIGN, pv(&mut ck_true), 1),
            attr(CKA_SENSITIVE, pv(&mut ck_true), 1),
            attr(CKA_EXTRACTABLE, pv(&mut ck_false), 1),
        ];
        let (mut c_pub, mut c_priv): (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) = (0, 0);
        ck!(
            derive_key_pair(
                session,
                &mut dmech,
                m_priv,
                cpub_tmpl.as_mut_ptr(),
                cpub_tmpl.len() as CK_ULONG,
                cpriv_tmpl.as_mut_ptr(),
                cpriv_tmpl.len() as CK_ULONG,
                &mut c_pub,
                &mut c_priv,
            ),
            "C_DeriveKeyPair(child)"
        );
        println!("child keypair: pub={c_pub} priv={c_priv}");

        let child_point = read_var(fl, session, c_pub, CKA_EC_POINT)?;
        let child_cc = read_var(fl, session, c_priv, CKA_SLIP10_CHAIN_CODE)?;
        println!("child EC point: {}", hex::encode(&child_point));
        println!("child chain code: {}", hex::encode(&child_cc));

        // ---- ECDSA sign a 32-byte digest with the child private key ----
        let digest = [0x9au8; 32];
        let mut smech = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        ck!(f!(C_SignInit)(session, &mut smech, c_priv), "C_SignInit");
        let mut siglen: CK_ULONG = 0;
        ck!(
            f!(C_Sign)(
                session,
                digest.as_ptr() as *mut u8,
                digest.len() as CK_ULONG,
                ptr::null_mut(),
                &mut siglen
            ),
            "C_Sign(len)"
        );
        let mut sig = vec![0u8; siglen as usize];
        ck!(
            f!(C_Sign)(
                session,
                digest.as_ptr() as *mut u8,
                digest.len() as CK_ULONG,
                sig.as_mut_ptr(),
                &mut siglen
            ),
            "C_Sign"
        );
        sig.truncate(siglen as usize);
        println!("signature ({} bytes): {}", sig.len(), hex::encode(&sig));

        // ---- Host-side verify with secp256k1 ----
        verify(&child_point, &digest, &sig)?;
        println!("secp256k1 verify: OK");

        // cleanup (ephemeral objects auto-reap on session close, but be tidy)
        let _ = f!(C_DestroyObject)(session, c_priv);
        let _ = f!(C_DestroyObject)(session, c_pub);
        let _ = f!(C_DestroyObject)(session, m_priv);
        let _ = f!(C_DestroyObject)(session, m_pub);
        let _ = f!(C_Logout)(session);
        let _ = f!(C_CloseSession)(session);
        let _ = f!(C_Finalize)(ptr::null_mut());
    }
    Ok(())
}

/// Two-pass read of a variable-length attribute.
unsafe fn read_var(
    fl: CK_FUNCTION_LIST_PTR,
    session: CK_SESSION_HANDLE,
    obj: CK_OBJECT_HANDLE,
    t: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, String> {
    let get = unsafe { (*fl).C_GetAttributeValue }.ok_or("C_GetAttributeValue null")?;
    let mut a = [attr(t, ptr::null_mut(), 0)];
    let rv = unsafe { get(session, obj, a.as_mut_ptr(), 1) };
    if rv != CKR_OK {
        return Err(format!("C_GetAttributeValue(size 0x{t:x}) rv=0x{rv:x}"));
    }
    let len = a[0].ulValueLen as usize;
    let mut buf = vec![0u8; len];
    a[0].pValue = buf.as_mut_ptr() as *mut c_void;
    a[0].ulValueLen = len as CK_ULONG;
    let rv = unsafe { get(session, obj, a.as_mut_ptr(), 1) };
    if rv != CKR_OK {
        return Err(format!("C_GetAttributeValue(val 0x{t:x}) rv=0x{rv:x}"));
    }
    Ok(buf)
}

/// Verify a raw 64-byte ECDSA sig over `digest` against a CKA_EC_POINT pubkey.
fn verify(ec_point_der: &[u8], digest: &[u8; 32], sig: &[u8]) -> Result<(), String> {
    use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
    // CKA_EC_POINT is a DER OCTET STRING wrapping the SEC point.
    let point = if ec_point_der.first() == Some(&0x04) && ec_point_der.len() >= 2 {
        // 0x04 = OCTET STRING tag; next byte(s) = length. Short form only here.
        &ec_point_der[2..]
    } else {
        ec_point_der
    };
    let pk = PublicKey::from_slice(point)
        .map_err(|e| format!("pubkey parse: {e} (point={})", hex::encode(point)))?;
    if sig.len() != 64 {
        return Err(format!("expected 64-byte ecdsa sig, got {}", sig.len()));
    }
    let mut signature = Signature::from_compact(sig).map_err(|e| format!("sig parse: {e}"))?;
    // HSMs often emit high-S; libsecp256k1 verify requires low-S (BIP-62).
    signature.normalize_s();
    let msg = Message::from_digest_slice(digest).map_err(|e| format!("msg: {e}"))?;
    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &signature, &pk)
        .map_err(|e| format!("verify: {e}"))
}
