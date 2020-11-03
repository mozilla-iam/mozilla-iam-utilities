#!/usr/bin/env python3

import sys

from urllib.parse import unquote

from .utils import get_auth0_management_session

# make sure there's an id present
if len(sys.argv) != 2:
    print("No user id or file name provided. Exiting.")
    sys.exit(1)

user_ids = [unquote(sys.argv[1].strip())]

# start an auth0 management api session
auth0 = get_management_session()

for user_id in user_ids:
    if not user_id:
        continue

    try:
        # get the user's metadata, set existsInCIS to false, and then repost
        metadata = {
            "user_metadata": auth0.users.get(user_id).get("user_metadata", {})
        }
        metadata["user_metadata"]["existsInCIS"] = False

        auth0.users.update(user_id, metadata)

        print(f"Successfully set existsInCIS to false for: {user_id}")
    except:
        print(f"Unable to update user: {user_id}")
        raise
