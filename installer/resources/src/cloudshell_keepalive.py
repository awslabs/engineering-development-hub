# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import threading
import time
import json
import boto3
import botocore.session
import botocore.exceptions
import sys
import argparse

_additional_modes = """
{
  "metadata": {
    "apiVersion": "2019-03-01",
    "endpointPrefix": "cloudshell",
    "protocol": "rest-json",
    "serviceId": "CloudShell",
    "signatureVersion": "v4",
    "signingName": "cloudshell",
    "uid": "cloudshell-2019-03-01"
  },
  "operations": {
    "DescribeEnvironments": {
      "name": "DescribeEnvironments",
      "http": { "method": "POST", "requestUri": "/describeEnvironments" },
      "input": { "shape": "EmptyInput" },
      "output": { "shape": "DescribeEnvironmentsOutput" }
    },
    "SendHeartBeat": {
      "name": "SendHeartBeat",
      "http": { "method": "POST", "requestUri": "/sendHeartBeat" },
      "input": { "shape": "EnvironmentIdInput" }
    }
  },
  "shapes": {
    "EmptyInput": {
      "type": "structure",
      "members": {}
    },
    "EnvironmentIdInput": {
      "type": "structure",
      "required": ["EnvironmentId"],
      "members": {
        "EnvironmentId": { "shape": "String" }
      }
    },
    "DescribeEnvironmentsOutput": {
      "type": "structure",
      "members": {
        "Environments": { "shape": "EnvironmentList" }
      }
    },
    "EnvironmentList": {
      "type": "list",
      "member": { "shape": "EnvironmentOutput" }
    },
    "EnvironmentOutput": {
      "type": "structure",
      "members": {
        "EnvironmentId": { "shape": "String" },
        "Status":        { "shape": "String" }
      }
    },
    "String": { "type": "string" }
  }
}
"""

_MODEL_DATA = json.loads(_additional_modes)
_SERVICE    = 'cloudshell'
_TYPE       = 'service-2'
_VERSION    = '2019-03-01'

bc_session = botocore.session.get_session()
loader = bc_session.get_component('data_loader')

# Patch the three methods botocore calls so the model is served from memory.
_orig_load = loader.load_service_model
_orig_list = loader.list_available_services
_orig_ver  = loader.determine_latest_version

def _load(service_name: str, type_name: str, api_version: str | None = None) -> dict:
    if service_name == _SERVICE and type_name == _TYPE:
        return _MODEL_DATA
    return _orig_load(service_name, type_name, api_version)

def _list(type_name: str) -> list[str]:
    services = list(_orig_list(type_name))
    if type_name == _TYPE and _SERVICE not in services:
        services.append(_SERVICE)
    return services

def _ver(service_name: str, type_name: str) -> str:
    if service_name == _SERVICE and type_name == _TYPE:
        return _VERSION
    return _orig_ver(service_name, type_name)

loader.load_service_model       = _load
loader.list_available_services  = _list
loader.determine_latest_version = _ver


def _build_client(region: str) -> boto3.Session:
    bc = botocore.session.get_session()
    ldr = bc.get_component('data_loader')
    ldr.load_service_model       = _load
    ldr.list_available_services  = _list
    ldr.determine_latest_version = _ver
    return boto3.Session(botocore_session=bc).client(_SERVICE, region_name=region)

def heartbeat_loop(region: str, env_id: str, interval: int = 300, max_runtime: int = 5400) -> None:
    _client = _build_client(region)
    deadline = time.monotonic() + max_runtime
    print(f"Heartbeat loop started — interval={interval}s max_runtime={max_runtime}s")
    while time.monotonic() < deadline:
        try:
            _client.send_heart_beat(EnvironmentId=env_id)
            print(f"Heartbeat sent for {env_id} at {time.asctime()}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ExpiredTokenException':
                print("AWS credentials expired — rebuilding client and retrying...")
                _client = _build_client(region)
                time.sleep(60)
                continue
            raise
        time.sleep(interval)
    print("Heartbeat loop reached maximum runtime — stopping.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keep a CloudShell environment alive via periodic heartbeats.")
    parser.add_argument("--region", type=str, help="AWS region (e.g. us-east-1)")
    parser.add_argument("--interval", type=int, default=300, help="Seconds between heartbeats (default: 300s or 5 minutes)")
    parser.add_argument("--max-runtime", type=int, default=5400, help="Maximum runtime in seconds (default: 5400s or 90 minutes)")
    args = parser.parse_args()

    if not args.region:
        _region = os.environ.get("AWS_DEFAULT_REGION", os.environ.get("AWS_REGION", None))
    else:
        _region = args.region

    if not _region:
        print("Region not specified. Run export AWS_DEFAULT_REGION=<region_name> and retry")
        sys.exit(1)

    response = _build_client(region=_region).describe_environments()
    if not response['Environments']:
        print("No active CloudShell environment found.")
        sys.exit(1)
    else:
        environment = response['Environments'][0].get("EnvironmentId")
    print(f"Starting KeepAlive for environment {environment}")
    t = threading.Thread(target=heartbeat_loop, args=(_region, environment, args.interval, args.max_runtime), daemon=True)
    t.start()
    t.join()
