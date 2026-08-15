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

import logging
from flask import render_template, Blueprint, session
from decorators import login_required, feature_flag
from utils.config import SocaConfig

logger = logging.getLogger("soca_logger")
my_activity = Blueprint("my_activity", __name__, template_folder="templates")


@my_activity.route("/my_activity", methods=["GET"])
@login_required
@feature_flag(flag_name="ANALYTICS_COST_MANAGEMENT", mode="view")
def index():
    _opensearch_endpoint = (
        SocaConfig(key="/configuration/Analytics/endpoint").get_value().get("message")
    )
    _opensearch_engine = (
        SocaConfig(key="/configuration/Analytics/engine").get_value().get("message")
    )
    _opensearch_enabled = (
        SocaConfig(key="/configuration/Analytics/enabled")
        .get_value(return_as=bool)
        .get("message")
    )
    user = session["user"]
    _is_serverless = _opensearch_engine in ("opensearch_serverless", "aoss_serverless")
    if _is_serverless:
        _dashboard_endpoint = None
    elif _opensearch_engine == "opensearch":
        _dashboard_endpoint = f"{_opensearch_endpoint}/_dashboards/"
    else:
        _dashboard_endpoint = f"{_opensearch_endpoint}/_plugin/kibana/"

    return render_template(
        "my_activity.html",
        dashboard_endpoint=_dashboard_endpoint,
        opensearch_engine=_opensearch_engine,
        opensearch_enabled=_opensearch_enabled,
        is_serverless=_is_serverless,
    )
