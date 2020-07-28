#!/usr/bin/env python3

#
# requires ~/.config/auth0/credentials.json, which looks like this:
# {
#     "client_id": "...",
#     "client_secret": "...",
#     "uri": "auth.mozilla.auth0.com"
# }
#
# run with a single id, such as:
# $ ./unexist-in-cis.py "ad|Mozilla-LDAP|apking"
#
# Or process a list of user ids, such as:
# ./unexist-in-cis.py list-of-users.txt
#

import json
import os.path
import sys

from urllib.parse import unquote

from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0

# make sure there's an id present
if len(sys.argv) != 2:
    print("No user id or file name provided. Exiting.")
    sys.exit(1)

user_ids = [unquote(sys.argv[1].strip())]

# check to see if we were provided a file name instead
if "|" not in user_ids[0] and os.path.exists(user_ids[0]):
    with open(user_ids[0], "r") as __f:
        user_ids = []
        for line in __f:
            user_ids.append(unquote(line).strip())

# load auth0 configuration, ~/.config/auth0/credentials
config = os.path.expanduser(os.path.join("~", ".config", "auth0", "credentials.json"))
if not os.path.exists(config):
    print(f"Can't open {config}, exiting.")
    sys.exit(1)

with open(config, "r") as __f:
    config = json.load(__f)

if ("client_id" not in config or
    "client_secret" not in config or
    "uri" not in config):
    print(f"{config} is missing configuration settings.")
    sys.exit(1)

try:
    # get the auth0 access token
    token = GetToken(config["uri"]).client_credentials(
        config["client_id"],
        config["client_secret"],
        f"https://{config['uri']}/api/v2/"
    ).get("access_token")

    if not token:
        raise ValueError
except:
    print("Unable to get access token from Auth0")
    sys.exit(1)

# start an auth0 session with the new token
auth0 = Auth0(config["uri"], token)

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

