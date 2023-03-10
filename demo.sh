#!/usr/bin/env bash
dfx stop
# trap 'dfx stop' EXIT

dfx start --background --clean
dfx deploy authz_canister
AUTHZ_CAN_ID=$(dfx canister id authz_canister)

# Need to set root key of local replica as second argument if used locally
# There's probably a better way to do this
ROOT_KEY=$(dfx ping | sed -n 's/.*"root_key": \(.*\)/\1/p' | sed 's/[][,]//g' | xargs printf "%02x" ) 
dfx deploy resource_canister --argument "(principal \"$AUTHZ_CAN_ID\", opt blob \"$ROOT_KEY\")"

MY_ID=$(dfx identity get-principal)
echo 'Setting permissions for '$MY_ID 'to use GET and INC but not SET...'
dfx canister call authz_canister update_permissions "(principal \"$MY_ID\", \"get\", true)"
dfx canister call authz_canister update_permissions "(principal \"$MY_ID\", \"inc\", true)"

echo 'Requesting token..'
TOKEN=$(dfx canister call authz_canister read_permissions_certified | grep -o '".*"')

SIZE=$(echo $TOKEN | wc -c)
echo "Token size in bytes: $SIZE"

echo 'Get counter value with token...'
time dfx canister call resource_canister get "(opt blob $TOKEN,)"


echo 'Increment counter value with token...'
time dfx canister call resource_canister inc "(opt blob $TOKEN,)"

echo 'Increment counter value without token...'
time dfx canister call resource_canister inc "(null,)"

echo 'Get counter value without token using composite query...'
time dfx canister call resource_canister get_composite "(null,)"


echo 'Try to set counter value to 5 with token...'
dfx canister call resource_canister set "(5, opt blob $TOKEN)"

echo 'Get counter value with token...'
dfx canister call resource_canister get "(opt blob $TOKEN,)"

dfx stop