
use candid::Principal;
use ic_cdk::api::{data_certificate, set_certified_data, trap};
use ic_cdk_macros::{query, update};
use ic_certified_map::{AsHashTree, HashTree, RbTree};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::cell::RefCell;


thread_local! {
    static PERMISSIONS: RefCell<RbTree<Principal, RbTree<String, Vec<u8>>>> = RefCell::new(RbTree::new());
}


#[query]
fn verify_permissions(user: Principal, action: String) -> bool {
 
    PERMISSIONS.with(|permissions| {
        let permissions = permissions.borrow();
        let user_permissions  = permissions.get(user.as_ref());
        if let Some(user_permissions) = user_permissions {
            user_permissions.get(action.as_ref()).is_some()
        } else {
            false
        }
    })
}


#[query]
fn read_permissions_certified() -> Option<Vec<u8>> {
 
    let certificate = data_certificate().unwrap_or_else(|| {
        trap("data certificate is only available in query calls");
    });

    let user = ic_cdk::caller();

    PERMISSIONS.with(|permissions| {
        let permissions = permissions.borrow();
        let tree = permissions.witness(user.as_ref());

        #[derive(Serialize)]
        struct Sig<'a> {
            certificate: ByteBuf,
            tree: HashTree<'a>,
        }
    
        let sig = Sig {
            certificate: ByteBuf::from(certificate),
            tree,
        };
    
        let mut cbor = serde_cbor::ser::Serializer::new(Vec::new());
        cbor.self_describe().unwrap();
        sig.serialize(&mut cbor).unwrap();
        Some(cbor.into_inner())
    })

   
}

// Update permissions for a user
// This method needs to be guarded such that only an admin can update permissions
#[update]
fn update_permissions(user: Principal, resource: String, has_permission: bool) -> String {
    PERMISSIONS.with(|permissions| {
        let mut permissions = permissions.borrow_mut();

        if permissions.get(user.as_ref()).is_none() {

            let mut user_permissions = RbTree::new();
            user_permissions.insert(resource, vec![1]); 
            permissions.insert(user, user_permissions.clone());

        } else {
            permissions.modify(user.as_ref() , |user_permissions| {
                if has_permission {
                    user_permissions.insert(resource, vec![1]);
                } else {
                  user_permissions.delete(resource.as_ref());
                } 
            });
           
        }
        
        set_certified_data(&permissions.root_hash());
        format!("Updated permissions for user: {}", user)
    })
}
