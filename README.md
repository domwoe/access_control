# Access Control on the Internet Computer

## Motivation

In microservice architectures, it's common to centralize access control by having a single authorization service that manages all permissions. This simplifies permission management but raises the question of how resource services learn about the permissions. There are two main patterns:

1) Tokens: A client requests an authorization token from the authorization service and invokes it at the resource service. Here, the resource service does not need to directly communicate with the authorization service.
2) Validation endpoint: The authorization server exposes a validation endpoint that the resource service can use to validate permissions.


On the Internet Computer, we can use the same patterns and this example application demonstrates these patterns.

## Architecture

We have the following two canisters:

1) Authorization Canister

The authorization canister has the following interface:

```
type token = blob;
type target = text;
service : {
    "update_permissions": (principal, target, bool) -> (text); // update permissions of a specific user and target (by its function name)
    "read_permissions_certified": ()              -> (opt token) query; // fetch permissions as token
    "verify_permissions": (principal, target)       -> (bool) query; // verify permissions
}
```

The permissions are maintained in a certified data structure using the `ic-certified-map` crate and the certified data functionality of the Internet Computer. When a client fetches the token with the `read_permissions_certified` function, then this token includes a path to the state root hash of the Internet Computer and a signature. Thereby, the resource canister can verify the authenticity of the token and the client can't tamper with the token.
 

2) Resource canister

The resource canister is the [counter example canister](https://github.com/dfinity/examples/tree/master/rust/counter) with added permissions.

```
type token = blob;
service : (principal) -> {
    "get": (opt token)      -> (nat) query;
    "get_composite": (opt blob) -> (nat) query;
    "set": (nat, opt token) -> ();
    "inc": (opt token)      -> ();
```
Note that we have to provide a principal as an init argument. This allows to register the authorization canister. We need the principal of the authorization canister to verify that the tokens have been "signed" by the authorization canister, or to know how to call the `verify_permissions` endpoints.

Furthermore, we note that each endpoint has an optional argument to provide the authorization token, and that there's an additional endpoint called `get_composite`. This is a composite query that allows to do an inter-canister query call to the `verify_permissions` endpoint.


### Demo Flow

You can run a demo flow 

```
./demo.sh
```

It will also show the runtime of the commands.