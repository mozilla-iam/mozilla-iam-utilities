#!/usr/bin/env python3

import json
import os
import logging
import sys

from collections import defaultdict
from deepdiff import DeepDiff

from auth0.v3 import Auth0Error
from mozilla_iam_utils.utils import get_auth0_config, get_auth0_management_session


# first, we need to get an auth0 management API token
domain = get_auth0_config()["uri"]
auth0 = get_auth0_management_session()

CONNECTION_SUPREMACY_ORDER = ("Mozilla-LDAP", "Mozilla-LDAP-Dev", "firefoxaccounts",
                              "github", "google-oauth2", "email", "unknown")


# set the log level, if we have the environmental variable set
if os.environ.get("LOGLEVEL"):
    logging.basicConfig(level=getattr(logging, os.environ["LOGLEVEL"].upper()))

def get_primary_user_id_from_user_ids(user_ids: dict) -> str:
    # first things first, we can't have two accounts that need linking where each has more than one identity
    user_ids_with_linked_identities = [user_id for user_id, user in user_ids.items() if user["identities_count"] > 1]

    if len(user_ids_with_linked_identities) > 1:
        logging.error(f"Can't link accounts since {' & '.join(user_ids_with_linked_identities)} each contain linked accounts")
        raise ValueError

    # if there exists an account with linked identities, it is the primary
    elif len(user_ids_with_linked_identities) == 1:
        return user_ids_with_linked_identities[0]

    # otherwise, we have to look at which identity has the highest priority
    else:
        # this is O(horrendous), but it doesn't matter because it's still really fast
        for connection in CONNECTION_SUPREMACY_ORDER:
            for user_id, user in user_ids.items():
                if user["connection"] == connection:
                    return user_id

    # this should never happen - it would mean multiple user_ids, none of which have a known connection type
    raise UserWarning

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
    # open up the export of all users, created by `export-all-auth0-users.py`
    with open(f"{domain}-users.json", "r") as __f:
        all_users = json.load(__f)
    logging.info(f"Found {len(all_users)} accounts inside auth0")


    # next, we need to create a mapping of email addresses -> bound user ids
    emails_to_userids = defaultdict(lambda: {})

    # first, we need to go through all the top level users and bind their email address to the user identity(ies)
    for user_id, user in all_users.items():
        if "email" not in user:
            logging.error(f"{user_id} doesn't have a bound email address")
            continue

        email = user["email"]

        # add the user_id to the list of known user_ids bound to that email address
        emails_to_userids[email][user_id] = {
            "app_metadata": user.get("app_metadata", {}),
            "connection": user["identities"][0]["connection"],
            "identities_count": len(user["identities"]),
            "provider": user["identities"][0]["provider"],
            "user_id": user_id,
            "user_metadata": user.get("user_metadata", {}),
        }

    # next, we need to loop through again and find any identities that have email mismatches - if they do,
    # we need to move any unlinked account for that email address into the primary account
    for user_id, user in all_users.items():
        for identity in user.get("identities", [])[1:]:  # ignore the first identity
            email = user.get("email")
            if not email is None:
                continue

            identity_email = identity.get("profileData", {}).get("email")
            identity_user_id = identity_to_user_id(identity)

            if not identity_email:
                continue

            if identity_email != email:
                logging.warning(f"{user_id} has an email mismatch across linked accounts: {email} & {identity_email}")

                if identity_email in emails_to_userids:
                    # If a user has account with primary email A and a linked account with email B, then that
                    # means that they changed their email address at some point. If we encounter this, look to see
                    # if they have any unlinked accounts bound to email B, and move them into the account bound
                    # to primary email A

                    # NOTE: We decided not to do this

                    # for unlinked_identity_user_id, unlinked_identity in emails_to_userids[identity_email].items():
                    #     emails_to_userids[email][unlinked_identity_user_id] = unlinked_identity
                    #     logging.info(f"Binding unlinked account for {identity_email} ({identity_to_user_id(unlinked_identity)}) into account for {email} ({user_id})")
                    #
                    # del emails_to_userids[identity_email]
                    pass


    # remove all accounts with only one user_id, for efficiency and logging purposes
    emails_to_userids = {email: user_ids for email, user_ids in emails_to_userids.items() if len(user_ids) > 1}

    # hey, how many email addresses do we need to link?
    logging.info(f"Found {len(emails_to_userids)} accounts that require linking.")

    # Just trying to clean up the debugger, don't mind me
    del(identity)
    del(user)

    # now, we need to go through each of the emails with more than one id, and find the "primary" account
    # that we'll be linking into
    for email, user_ids in emails_to_userids.items():
        try:
            primary_user_id = get_primary_user_id_from_user_ids(user_ids)
            secondary_user_ids = [user_id for user_id in user_ids.keys() if user_id != primary_user_id]
        except ValueError:
            continue

        # log how the linking will work
        logging.info(f"{primary_user_id} ({email}) <-- {', '.join(secondary_user_ids)}")

        for secondary_user_id in secondary_user_ids:
            primary_user_app_metadata = user_ids[primary_user_id]["app_metadata"]
            secondary_user_app_metadata = user_ids[secondary_user_id]["app_metadata"]
            secondary_user_user_metadata = user_ids[secondary_user_id]["user_metadata"]
            exists_in_cis = secondary_user_user_metadata.pop("existsInCIS", True)

            # Remove useless metadata
            if "groups" in secondary_user_app_metadata and len(secondary_user_app_metadata["groups"]) == 0:
                del secondary_user_app_metadata["groups"]

            if secondary_user_user_metadata:
                logging.warning(f"User {secondary_user_id} has user metadata: {secondary_user_user_metadata}")

            if (primary_user_app_metadata and secondary_user_app_metadata) and DeepDiff(primary_user_app_metadata, secondary_user_app_metadata, ignore_order=True):
                logging.error("Both primary account and linked account have conflicting app_metadata - aborting")

                if exists_in_cis:
                    logging.info(f"Secondary account {secondary_user_id} exists in CIS, cannot delete - manually fix.")
                else:
                    logging.info(f"Secondary account {secondary_user_id} does not exist in CIS, can delete.")
                    # auth0.users.delete(secondary_user_id)

                continue
            elif (primary_user_app_metadata and secondary_user_app_metadata) and not DeepDiff(primary_user_app_metadata, secondary_user_app_metadata, ignore_order=True):
                logging.info("Both primary and linked account have identical app_metadata")
            elif secondary_user_app_metadata and not primary_user_app_metadata:
                logging.warning(f"User {secondary_user_id} has app metadata: {secondary_user_app_metadata}, merging into {primary_user_id}")

                # update the primary accounts metadata
                auth0.users.update(primary_user_id, {"app_metadata": secondary_user_app_metadata})

                logging.info(f"Successfully migrated {secondary_user_id}'s app metadata into {primary_user_id}")


            # link the accounts
            if exists_in_cis == False:
                try:
                    auth0.users.link_user_account(primary_user_id, { "provider": user_ids[secondary_user_id]["provider"], "user_id": user_ids[secondary_user_id]["user_id"]})

                    logging.info(f"Linked {secondary_user_id} into {primary_user_id} for {email}")
                except Auth0Error as e:
                    if "400" in str(e) or "409" in str(e):
                        logging.info(f"{secondary_user_id} has already been linked into {primary_user_id} from previous run.")
                    else:
                        logging.fatal(f"Linking error attempting to link {secondary_user_id} ({email}) into {primary_user_id}: {e}")
                        sys.exit(-1)
