#!/usr/bin/env python3

import os.path
import sys

from urllib.parse import unquote

from mozilla_iam_utils.utils import get_auth0_management_session

# make sure there's an id present
if len(sys.argv) != 2:
    print("No user id or file name provided. Exiting.")
    sys.exit(1)

if os.path.exists(sys.argv[1]):
    with open(sys.argv[1], "r") as __f:
        user_ids = [unquote(user_id).strip() for user_id in __f]
else:
    user_ids = [unquote(sys.argv[1].strip())]


# start an auth0 management api session
auth0 = get_auth0_management_session()

for user_id in user_ids:
    if not user_id:
        continue

    # contact auth0, get the full list of parent user_ids matching this user_id
    identity_user_id = "|".join(user_id.split("|")[1:])
    auth0_users = auth0.users.list(q=f'user_id:"{user_id}" OR identities.user_id:"{identity_user_id}"')["users"]

    if len(auth0_users) != 1:
        print(f"User search found more or less than one user - exiting.")
        exit()

    # Now, we have the real user_id of the parent
    parent_user_id = auth0_users[0]["user_id"]

    try:
        # get the user's metadata, set existsInCIS to false, and then repost
        metadata = {
            "user_metadata": auth0.users.get(parent_user_id).get("user_metadata", {})
        }
        metadata["user_metadata"]["existsInCIS"] = False

        auth0.users.update(parent_user_id, metadata)

        if user_id == parent_user_id:
            print(f"Successfully set existsInCIS to false for {parent_user_id}")
        else:
            print(f"Successfully set existsInCIS to false for {parent_user_id} on identity {user_id}")
    except:
        print(f"Unable to update user: {parent_user_id}")
        raise
