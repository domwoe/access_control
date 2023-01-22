use candid::{types::number::Nat, Principal};
use ic_cdk::api::{caller, trap};
use ic_cdk_macros::{init, query, update};
use ic_certification::{Certificate, HashTree, LookupResult};
// use ic_verify_bls_signature::verify_bls_signature;
use std::cell::RefCell;

use serde_bytes::ByteBuf;
use serde_cbor::de::from_mut_slice;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
struct Sig<'a> {
    certificate: ByteBuf,
    tree: HashTree<'a>,
}

// const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

#[init]
fn init(authz_canister_id: Principal) {
    // Set the initial value of the counter.
    AUTHZ_CANISTER_ID.with(|canister_id| *canister_id.borrow_mut() = authz_canister_id);
}

thread_local! {
    static COUNTER: RefCell<Nat> = RefCell::new(Nat::from(0));
    static AUTHZ_CANISTER_ID: RefCell<Principal> = RefCell::new(Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap());
}

/// Get the value of the counter.
#[query]
fn get(token: Option<Vec<u8>>) -> Nat {
    let is_allowed = match token {
        Some(token) => verify_token("get", token),
        None => false
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
        None => verify_remote_permissions("get").await
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
        None => verify_remote_permissions("set").await
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
        None => verify_remote_permissions("inc").await
    };
    if !is_allowed {
        trap(&format!("Caller {} is not allowed to call inc", caller()));
    }
    COUNTER.with(|counter| *counter.borrow_mut() += 1);
}

/// Verify by permissions by calling the authz canister
async fn verify_remote_permissions(action: &str) -> bool {

    let authz_canister_id = AUTHZ_CANISTER_ID.with(|authz_canister_id| (*authz_canister_id.borrow()));

    match ic_cdk::call(authz_canister_id, "verify_permissions", (caller(), action.to_string())).await {
        Ok((is_allowed,)) => is_allowed,
        Err(_) => false,
    }
}

/// Verify the token
//TODO: Validate time and signature including delegation
fn verify_token(action: &str, mut token: Vec<u8>) -> bool {
    let sig: Sig = from_mut_slice(&mut token[..]).unwrap();
    let certificate: Certificate = serde_cbor::from_slice(&sig.certificate[..]).unwrap();

    let authz_canister_id =
        AUTHZ_CANISTER_ID.with(|authz_canister_id| (*authz_canister_id.borrow()));

    // Check if root hash of the permissions hash tree matches the certified data in the certificate

    let certified_data_path = [
        "canister".into(),
        authz_canister_id.into(),
        "certified_data".into(),
    ];

    // Get value of the certified data in the certificate
    let witness = match certificate.tree.lookup_path(&certified_data_path) {
        LookupResult::Found(witness) => witness,
        _ => return false,
    };

    // Recompute the root hash of the permissions hash tree
    let digest = sig.tree.digest();
    if witness != digest {
        return false;
    }

    // Check if the caller is authorized to call the action
    // We do this by checking if the following patch exists in the hash tree:
    let path = [caller().into(), action.into()];

    matches!(sig.tree.lookup_path(&path), LookupResult::Found(_))

}

// fn verify(
//     cert: &Certificate,
//     effective_canister_id: Principal,
// ) -> bool {
//     let sig = &cert.signature;

//     let root_hash = cert.tree.digest();
//     let mut msg = vec![];
//     // msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
//     msg.extend_from_slice(&root_hash);

//     let der_key = check_delegation(&cert.delegation, effective_canister_id)?;
//     let key = extract_der(der_key)?;

//     ic_verify_bls_signature::verify_bls_signature(sig, &msg, &key)
//         .map_err(|_| AgentError::CertificateVerificationFailed())
// }

// fn check_delegation(
//     delegation: &Option<Delegation>,
//     effective_canister_id: Principal,
// ) -> Vec<u8> {
//     match delegation {
//         None => read_root_key(),
//         Some(delegation) => {
//             let cert: Certificate = serde_cbor::from_slice(&delegation.certificate).unwrap();

//             verify(&cert, effective_canister_id);
//             let canister_range_lookup = [
//                 "subnet".into(),
//                 delegation.subnet_id.clone().into(),
//                 "canister_ranges".into(),
//             ];
//             let canister_range = lookup_value(&cert, canister_range_lookup);
//             let ranges: Vec<(Principal, Principal)> =
//                 serde_cbor::from_slice(canister_range).iunwrap();
//             if !principal_is_within_ranges(&effective_canister_id, &ranges[..]) {
//                 // the certificate is not authorized to answer calls for this canister
//                 trap("Delegation invalid");
//             }

//             let public_key_path = [
//                 "subnet".into(),
//                 delegation.subnet_id.clone().into(),
//                 "public_key".into(),
//             ];
//             lookup_value(&cert, public_key_path).map(|pk| pk.to_vec())
//         }
//     }
// }
