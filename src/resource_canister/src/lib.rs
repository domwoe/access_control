use candid::{types::number::Nat, Principal};
use ic_cdk::api::{caller, trap};
use ic_cdk_macros::{init, query, update};
use ic_certification::{Certificate, Delegation, HashTree, LookupResult};
use ic_verify_bls_signature::{verify_bls_signature};
use std::cell::RefCell;

use serde_bytes::ByteBuf;
use serde_cbor::de::from_mut_slice;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
struct Token<'a> {
    certificate: ByteBuf,
    tree: HashTree<'a>,
}

const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
const KEY_LENGTH: usize = 96;

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";

const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";
const TOKEN_EXPIRATION: u128 = 15 * 60 * 1000 * 1000 * 1000; // 15 minutes in ns

#[init]
fn init(authz_canister_id: Principal, ic_root_key: Option<Vec<u8>> ) {
    // Set the initial value of the counter.
    AUTHZ_CANISTER_ID.with(|canister_id| *canister_id.borrow_mut() = authz_canister_id);

   if let Some(ic_root_key) = ic_root_key {
        ROOT_KEY.with(|root_key| *root_key.borrow_mut() = ic_root_key);
    } else {
        ROOT_KEY.with(|root_key| *root_key.borrow_mut() = IC_ROOT_KEY.to_vec());
    }
}

thread_local! {
    static ROOT_KEY: RefCell<Vec<u8>> = RefCell::new(IC_ROOT_KEY.to_vec());
    static COUNTER: RefCell<Nat> = RefCell::new(Nat::from(0));
    static AUTHZ_CANISTER_ID: RefCell<Principal> = RefCell::new(Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap());
}

/// Get the value of the counter.
#[query]
fn get(token: Option<Vec<u8>>) -> Nat {
    let is_allowed = match token {
        Some(token) => verify_token("get", token),
        None => false,
    };
    if !is_allowed {
        trap(&format!("Caller {} is not allowed to call get", caller()));
    }
    COUNTER.with(|counter| (*counter.borrow()).clone())
}

/// Get the value of the counter
/// This method is marked as a composite query and as such can call the verify query of the authz canister    
#[query(composite = true)]
async fn get_composite(token: Option<Vec<u8>>) -> Nat {
    let is_allowed = match token {
        Some(token) => verify_token("get", token),
        None => verify_remote_permissions("get").await,
    };
    if !is_allowed {
        trap(&format!("Caller {} is not allowed to call get", caller()));
    }
    COUNTER.with(|counter| (*counter.borrow()).clone())
}

/// Set the value of the counter.
#[update]
async fn set(n: Nat, token: Option<Vec<u8>>) {
    let is_allowed = match token {
        Some(token) => verify_token("set", token),
        None => verify_remote_permissions("set").await,
    };
    if !is_allowed {
        trap(&format!("Caller {} is not allowed to call set", caller()));
    }
    COUNTER.with(|count| *count.borrow_mut() = n);
}

/// Increment the value of the counter.
#[update]
async fn inc(token: Option<Vec<u8>>) {
    let is_allowed = match token {
        Some(token) => verify_token("inc", token),
        None => verify_remote_permissions("inc").await,
    };
    if !is_allowed {
        trap(&format!("Caller {} is not allowed to call inc", caller()));
    }
    COUNTER.with(|counter| *counter.borrow_mut() += 1);
}

/// Verify by permissions by calling the authz canister
async fn verify_remote_permissions(action: &str) -> bool {
    let authz_canister_id =
        AUTHZ_CANISTER_ID.with(|authz_canister_id| (*authz_canister_id.borrow()));

    match ic_cdk::call(
        authz_canister_id,
        "verify_permissions",
        (caller(), action.to_string()),
    )
    .await
    {
        Ok((is_allowed,)) => is_allowed,
        Err(_) => false,
    }
}

/// Verify the token
fn verify_token(action: &str, mut token: Vec<u8>) -> bool {
    let token: Token = from_mut_slice(&mut token[..]).unwrap();
    let certificate: Certificate = serde_cbor::from_slice(&token.certificate[..]).unwrap();

    let authz_canister_id =
        AUTHZ_CANISTER_ID.with(|authz_canister_id| (*authz_canister_id.borrow()));

    // Validate timestamp
    let current_time_ns = ic_cdk::api::time() as u128;

    validate_certificate_time(&certificate, &current_time_ns, &TOKEN_EXPIRATION);

    // Check if root hash of the permissions hash tree matches the certified data in the certificate

    let certified_data_path = [
        "canister".into(),
        authz_canister_id.into(),
        "certified_data".into(),
    ];

    // Get value of the certified data in the certificate
    let witness = match certificate.tree.lookup_path(&certified_data_path) {
        LookupResult::Found(witness) => witness,
        _ => trap("Certified data not found in certificate")
    };

    // Recompute the root hash of the permissions hash tree
    let digest = token.tree.digest();
    if witness != digest {
        trap("Root hash of the permissions hash tree does not match the certified data in the certificate")
    }

    // Check if the caller is authorized to call the action
    // We do this by checking if the following patch exists in the hash tree:
    let path = [caller().into(), action.into()];

    if !matches!(token.tree.lookup_path(&path), LookupResult::Found(_)) {
        trap("User does not have permission to call this action")
    }


    // Cryptographic validation of the certificate
    verify_certificate(&certificate, authz_canister_id)

}

// based on https://github.com/dfinity/response-verification/blob/50a32f26fe899a212cec35572e7097bff58b741c/packages/ic-response-verification/src/validation.rs#L6
fn validate_certificate_time(
    certificate: &Certificate,
    current_time_ns: &u128,
    allowed_certificate_time_offset: &u128,
) {
    let time_path = ["time".into()];

    let LookupResult::Found(encoded_certificate_time) = certificate.tree.lookup_path(&time_path) else {
        trap("Certificate does not contain a time field")
    };

    let certificate_time =
        leb128::read::unsigned(&mut encoded_certificate_time.as_ref()).unwrap() as u128;
    let max_certificate_time = current_time_ns + allowed_certificate_time_offset;
    let min_certificate_time = current_time_ns - allowed_certificate_time_offset;

    if certificate_time > max_certificate_time {
        trap(&format!("Certificate time is too far in the future. Certificate time: {}, current time: {}", certificate_time, current_time_ns))
    } else if certificate_time < min_certificate_time {
        trap(&format!("Certificate time is too far in the past. Certificate time: {}, current time: {}", certificate_time, current_time_ns))
    }
}

fn verify_certificate(
    cert: &Certificate,
    effective_canister_id: Principal,
) -> bool {
    let sig = &cert.signature;

    let root_hash = cert.tree.digest();
    let mut msg = vec![];
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);

    let der_key = validate_delegation(&cert.delegation, effective_canister_id);
    let key = extract_der(der_key);

    if verify_bls_signature(sig, &msg, &key).is_err() {
        trap("Certificate verification failed")
    }
    true
}

fn validate_delegation(
    delegation: &Option<Delegation>,
    effective_canister_id: Principal,
) -> Vec<u8> {
    match delegation {
        None => ROOT_KEY.with(|root_key| (*root_key.borrow()).clone()),
        Some(delegation) => {
            let cert: Certificate = serde_cbor::from_slice(&delegation.certificate).unwrap();

            verify_certificate(&cert, effective_canister_id);
            let canister_range_path = [
                "subnet".into(),
                delegation.subnet_id.clone().into(),
                "canister_ranges".into(),
            ];
            let LookupResult::Found(canister_range) = cert.tree.lookup_path(&canister_range_path) else {
                trap("Delegation invalid");
            };
            let ranges: Vec<(Principal, Principal)> =
                serde_cbor::from_slice(canister_range).unwrap();
            if !principal_is_within_ranges(&effective_canister_id, &ranges[..]) {
                // the certificate is not authorized to answer calls for this canister
                trap("The certificate is not authorized to answer calls for this canister");
            }

            let public_key_path = [
                "subnet".into(),
                delegation.subnet_id.clone().into(),
                "public_key".into(),
            ];
            let LookupResult::Found(pk) = cert.tree.lookup_path(&public_key_path) else {
                trap("Delegation invalid");
            };
            pk.to_vec()
        }
    }
}

// Taken from https://github.com/dfinity/agent-rs/blob/60f7a0db21688ca423dee0bb150e142a03e925c6/ic-agent/src/agent/response_authentication.rs#L9
fn extract_der(buf: Vec<u8>) -> Vec<u8> {
    let expected_length = DER_PREFIX.len() + KEY_LENGTH;
    if buf.len() != expected_length {
       trap(&format!("Invalid key length: {}", buf.len()));
    }

    let prefix = &buf[0..DER_PREFIX.len()];
    if prefix[..] != DER_PREFIX[..] {
        trap("Invalid key prefix");
    }

    let key = &buf[DER_PREFIX.len()..];
    key.to_vec()
}

// Checks if a principal is contained within a list of principal ranges
// A range is a tuple: (low: Principal, high: Principal), as described here: https://docs.dfinity.systems/spec/public/#state-tree-subnet
// Taken from https://github.com/dfinity/agent-rs/blob/60f7a0db21688ca423dee0bb150e142a03e925c6/ic-agent/src/agent/mod.rs#L784
fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
    ranges
        .iter()
        .any(|r| principal >= &r.0 && principal <= &r.1)
}

