import json
import os
import sys

from auth0.v3.management import Auth0
from auth0.v3.authentication import GetToken


def get_auth0_config() -> dict:
    """
    load auth0 configuration, ~/.config/auth0/credentials.json

    It should look like this:
    {
        "client_id": "client_id_here",
        "client_secret": "client_secret_here",
        "uri": "auth.mozilla.auth0.com"
    }

    :return: json version of credentials
    """

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

    return config

def get_auth0_token() -> str:
    config = get_auth0_config()

    try:
        # get the auth0 access token
        token = GetToken(config["uri"]).client_credentials(
            config["client_id"],
            config["client_secret"],
            f"https://{config['uri']}/api/v2/"
        ).get("access_token")

        if not token:
            raise ValueError

        return token
    except:
        print("Unable to get access token from Auth0")
        sys.exit(1)

def get_auth0_management_session():
    config = get_auth0_config()

    return Auth0(config["uri"], get_auth0_token())
