import json
import os

from cis_publishers.common import Profile


# This requires two environmental variables to be set:
# AUTH0_USERS_DUMP - as generated by `export-all-auth0-users.py`
# CIS_USERS_DUMP - as generated by `cis-inactive-user-cleanup.py dump`


def identity_to_user_id(identity: dict) -> str:
    user_id = identity["user_id"]

    if "ad|" in user_id or "oauth2|firefoxaccounts|" in user_id:
        return user_id
    elif "Mozilla-LDAP|" in user_id or "firefoxaccounts|" in user_id:
        return f"{identity['provider']}|{user_id}"
    elif "|" in user_id:
        return user_id
    else:
        return f"{identity['connection']}|{user_id}"


if __name__ == "__main__":
    all_cis_accounts = set()
    all_linked_accounts = set()

    # First, read in a list of all the linked identities in Auth0
    with open(os.environ["AUTH0_USERS_DUMP"], "r") as __f:
        auth0_users = json.load(__f)

    for user_id, user in auth0_users.items():
        for identity in user["identities"][1:]:
            all_linked_accounts.add(identity_to_user_id(identity))

    # Now, we need to read in all the identities in CIS
    with open(os.environ["CIS_USERS_DUMP"], "r") as __f:
        cis_users = json.load(__f)

    all_cis_accounts.update(cis_users.keys())

    # Here is the overlap of these two - ideally, it should be zero in length
    linked_accounts_in_cis = sorted(all_linked_accounts.intersection(all_cis_accounts))

    #print(f"{len(linked_accounts_in_cis)} linked accounts in CIS:\n\n{chr(10).join(linked_accounts_in_cis)}")
    # print("\n".join(linked_accounts_in_cis))

    with open("check-linked-children-in-cis.json", "w") as __f:
        json.dump({
            "users": linked_accounts_in_cis,
        }, __f, indent=2, sort_keys=True)

    for user_id in linked_accounts_in_cis:
        if not user_id.startswith("ad|Mozilla-LDAP"):
            try:
                profile = Profile(user_id=user_id)
            except:
                continue

            if not profile.is_empty():
                print(user_id)

#        print(f"{user_id} is{'' if profile.is_empty() else ' not'} empty")
