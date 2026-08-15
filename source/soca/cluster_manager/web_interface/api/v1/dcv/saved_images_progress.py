# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from flask_restful import Resource
from flask import request
from decorators import private_api, feature_flag
from models import db, VdiSavedImages
import utils.aws.boto3_wrapper as utils_boto3
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class SavedImagesProgress(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        _user = request.headers.get("X-EDH-USER")
        _rows = VdiSavedImages.query.filter_by(
            owner=_user, state="capturing", is_active=True
        ).all()
        if not _rows:
            return SocaResponse(success=True, message=[]).as_flask()
        _results = []
        for _r in _rows:
            _pct = 0
            try:
                _img = client_ec2.describe_images(ImageIds=[_r.image_id])
                _snap_ids = [
                    bdm["Ebs"]["SnapshotId"]
                    for i in _img.get("Images", [])
                    for bdm in i.get("BlockDeviceMappings", [])
                    if bdm.get("Ebs", {}).get("SnapshotId")
                ]
                if _snap_ids:
                    _snaps = client_ec2.describe_snapshots(SnapshotIds=_snap_ids)
                    _progs = []
                    for _s in _snaps.get("Snapshots", []):
                        _p = _s.get("Progress", "0%").rstrip("%")
                        try:
                            _progs.append(int(_p))
                        except ValueError:
                            _progs.append(0)
                    _pct = round(sum(_progs) / len(_progs)) if _progs else 0
            except Exception as err:
                logger.warning(f"SavedImagesProgress: {_r.image_id}: {err}")
            _results.append({"id": _r.id, "pct": _pct})
        return SocaResponse(success=True, message=_results).as_flask()
