#!/usr/bin/env bash

AUTHZ_CAN_ID=62hqk-naaaa-aaaap-qa5oa-cai
RESOURCE_CAN_ID=65gw6-ayaaa-aaaap-qa5oq-cai

MY_ID=$(dfx identity get-principal)
echo 'Setting permissions for '$MY_ID 'to use GET and INC but not SET...'
dfx canister call $AUTHZ_CAN_ID update_permissions "(principal \"$MY_ID\", \"get\", true)" --network=ic
dfx canister call $AUTHZ_CAN_ID update_permissions "(principal \"$MY_ID\", \"inc\", true)" --network=ic

echo 'Requesting token..'
TOKEN=$(dfx canister call $AUTHZ_CAN_ID read_permissions_certified --network=ic | grep -o '".*"')

echo 'Get counter value with token...'
time dfx canister call $RESOURCE_CAN_ID get "(opt blob $TOKEN,)" --network=ic


echo 'Increment counter value with token...'
time dfx canister call $RESOURCE_CAN_ID inc "(opt blob $TOKEN,)" --network=ic

echo 'Increment counter value without token...'
time dfx canister call $RESOURCE_CAN_ID inc "(null,)" --network=ic

echo 'Get counter value without token using composite query...'
time dfx canister call $RESOURCE_CAN_ID get_composite "(null,)" --network=ic


echo 'Try to set counter value to 5 with token...'
dfx canister call $RESOURCE_CAN_ID set "(5, opt blob $TOKEN)" --network=ic

echo 'Get counter value with token...'
dfx canister call $RESOURCE_CAN_ID get "(opt blob $TOKEN,)" --network=ic