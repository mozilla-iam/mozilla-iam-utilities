#!/usr/bin/env python3

import json

from mozilla_iam_utils.utils import get_auth0_config, get_auth0_management_session, get_auth0_token


# first, we need to get an auth0 management API token
domain = get_auth0_config()["uri"]
auth0 = get_auth0_management_session()

all_users = {}

page = 0

while True:
    users = auth0.users.list(page=page, per_page=100)

    if users["users"] == []:
        break

    for user in users["users"]:
        user_id = user["user_id"]

        all_users[user_id] = user

    print(f"Successfully retrieved page {page} ({len(all_users)} users)")

    # move onto the next page
    page += 1

# save the list of all users to disk
with open(f"{domain}-users.json", "w") as __f:
    json.dump(all_users, __f, indent=2, sort_keys=True)

    print(f"Successfully downloaded userlist for {domain} to {domain}-users.json")
