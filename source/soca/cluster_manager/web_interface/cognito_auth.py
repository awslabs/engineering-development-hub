######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import base64
import os
import config
import requests
from flask import session
from jose import jwt
from requests import get
import pwd
import logging
from utils.http_client import SocaHttpClient

"""
To enable SSO auth via cognito, update COGNITO section on config.py
https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/integrate-cognito-sso/
"""

logger = logging.getLogger("soca_logger")


def sso_authorization(code):
    authorization = (
        "Basic "
        + base64.b64encode(
            (
                config.Config.COGNITO_APP_ID + ":" + config.Config.COGNITO_APP_SECRET
            ).encode()
        ).decode()
    )
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": authorization,
    }

    data = {
        "grant_type": "authorization_code",
        "client_id": config.Config.COGNITO_APP_ID,
        "code": code,
        "redirect_uri": config.Config.COGNITO_CALLBACK_URL,
    }

    cognito_root_url = config.Config.COGNITO_OAUTH_TOKEN_ENDPOINT
    try:
        health_check = requests.get(cognito_root_url, timeout=5)
        if health_check.status_code != 200:
            logger.error(f"Cognito endpoint returned HTTP {health_check.status_code}: {cognito_root_url}")
            return {"success": False, "message": f"Cognito endpoint is not reachable (HTTP {health_check.status_code})"}
    except requests.RequestException as e:
        logger.error(f"Unable to reach Cognito endpoint {cognito_root_url}: {e}")
        return {"success": False, "message": "Cognito endpoint is not reachable. Check your network configuration."}
    except Exception as err:
        logger.error(f"Unexpected error while trying to authenticate against Cognito: {err}")
        return {"success": False, "message": "Unexpected error while trying to authenticate against Cognito"}
    oauth_token = requests.post(
        cognito_root_url, data=data, headers=headers
    ).json()
    id_token = oauth_token["id_token"]
    access_token = oauth_token["access_token"]
    headers = jwt.get_unverified_headers(id_token)
    keys = requests.get(config.Config.COGNITO_JWS_KEYS_ENDPOINT).json().get("keys")
    key = list(filter(lambda k: k["kid"] == headers["kid"], keys)).pop()
    claims = jwt.decode(
        id_token,
        key,
        access_token=access_token,
        algorithms=[key["alg"]],
        audience=config.Config.COGNITO_APP_ID,
    )
    if claims:
        logger.info(f"Received SSO claims: {claims}")
        try:
            _user_claim = config.Config.COGNITO_USER_CLAIM
            logger.info(
                f"Trying to retrieve user from SSO claims using claim: {_user_claim=}"
            )
            if claims.get(_user_claim, ""):
                if _user_claim in ["email", "mail"]:
                    user = claims[_user_claim].strip().split("@")[0]
                else:
                    logger.info(
                        f"user claim found with value {claims.get(_user_claim)}"
                    )
                    user = claims.get(_user_claim).strip()

            else:
                logger.error(
                    f"User specified claim {_user_claim} not found in received claims {claims}"
                )
                return {
                    "success": False,
                    "message": f"Unable to retrieve user/username/email from SSO claim {_user_claim}. Update config.py to change the user claim.  See logs for all detected claims.",
                }

        except Exception as err:
            logger.error(f"Unable to read SSO claims details due to {err}")
            return {
                "success": False,
                "message": "Error reading SSO claims. See logs for more details",
            }

        logger.info(
            f"Retrieved user {user=} from {claims.get('email')}, checking if user exists in people OU and sssd."
        )

        check_user = SocaHttpClient(
            endpoint="/api/ldap/user",
            headers={
                "X-EDH-TOKEN": config.Config.API_ROOT_KEY,
            },
        ).get(params={"user": user})

        if check_user.get("success"):
            logger.info("User exist in specified OU")
            try:
                pwd.getpwnam(user)
                logger.info(f"{user=} exists on this system.")
            except KeyError:
                logger.error(
                    f"{user=} does not exist on this system as pwd.getpwnam() failed. try to run id <user> and verify sssd.conf ."
                )
                return {
                    "success": False,
                    "message": "User is valid but does not seems to be available on the SOCA Controller. See log for more details.",
                }

            session["user"] = user
            return {"success": True, "message": ""}
        else:
            logger.error(
                f"Valid credentials but {user} could not be found in the specified OU. Verify specified People Base OU (/configuration/UserDirectory/people_search_base) and update it via cluster_manager/edhctl config set --key '/configuration/UserDirectory/people_search_base' --value 'MY_NEW_OU'  if needed. error {check_user.get('message')}"
            )
            return {
                "success": False,
                "message": "User could not be found in the directory OU. See logs for more details",
            }
    else:
        return {"success": False, "message": "SSO error. " + str(claims)}
