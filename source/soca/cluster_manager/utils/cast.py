# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Type, Literal, Union, get_args, get_origin
import logging
import ast
from typing import Dict
from utils.response import SocaResponse
from utils.error import SocaError
from utils.validators import Validators
import os
import sys
import json
import yaml
import enum
logger = logging.getLogger("soca_logger")


def auto_cast(data: Any, type_overrides: Dict[str, Type] = None, _path: str = "") -> Any:
    """
    Automatically cast a data to its intended type.
    - Supports nested list/dictionary.
    - Respects nested key overrides, e.g. {"key1.version": str} -> will force {"key1": {"version": "10.1"}} to be a str and not automatically cast to float or such
    """
    type_overrides = type_overrides or {}

    if _path in type_overrides:
        desired_type = type_overrides[_path]
        try:
            return desired_type(data)
        except Exception:
            return data

    if isinstance(data, str):
        try:
            low = data.lower()
            if low in SocaCastEngine.ALLOWED_TRUE_VALUES:
                return True
            elif low in SocaCastEngine.ALLOWED_FALSE_VALUES:
                return False
            else:
                parsed_value = ast.literal_eval(data)
                return parsed_value
        except (ValueError, SyntaxError):
            return data

    elif isinstance(data, list):
        return [auto_cast(item, type_overrides, _path) for item in data]

    elif isinstance(data, dict):
        result = {}
        for k, v in data.items():
            new_path = f"{_path}.{k}" if _path else k
            result[k] = auto_cast(v, type_overrides, new_path)
        return result

    return data


class SocaCastEngine:
    """
    Return None if we cannot cast the data as requested type
    """

    ALLOWED_FALSE_VALUES = ["false", "no", "off", "disabled"]
    ALLOWED_TRUE_VALUES = ["true", "yes", "on", "enabled"]

    def __init__(self, data: Any):
        self._data = data

    def cast_as(self, expected_type: Type):
        logger.debug(f"Trying to cast {self._data} as {expected_type}")
        _allowed_types = [bool, dict, float, int, list, set, str, tuple]
        if expected_type not in _allowed_types:
            return SocaError.CAST_ERROR(
                helper=f"Invalid type, must be one of {''.join(str(_allowed_types))}"
            )
        else:
            if self.is_type(expected_type=expected_type):
                return SocaResponse(success=True, message=self._data)
            else:
                try:
                    if isinstance(self._data, bytes):
                        logger.debug("bytes detected, casting it back as str first.")
                        self._data = self._data.decode()

                    if expected_type == bool:
                        # Cast specific str as bool
                        if (
                            str(self._data).lower()
                            in SocaCastEngine.ALLOWED_FALSE_VALUES
                        ):
                            return SocaResponse(success=True, message=False)
                        elif (
                            str(self._data).lower()
                            in SocaCastEngine.ALLOWED_TRUE_VALUES
                        ):
                            return SocaResponse(success=True, message=True)
                        else:
                            return SocaError.CAST_ERROR(
                                helper=f"{self._data} is not a valid bool value."
                            )

                    elif expected_type == dict:
                        try:
                            return SocaResponse(success=True, message=dict(self._data))
                        except Exception as _e:
                            _dict_cast = ast.literal_eval(
                                self._data.decode("utf-8")
                                if isinstance(self._data, bytes)
                                else self._data
                            )

                            if isinstance(_dict_cast, dict):
                                return SocaResponse(success=True, message=_dict_cast)
                            else:
                                return SocaError.CAST_ERROR(
                                    helper=f"Unable to cast {self._data} as dict because of {_e}"
                                )
                    elif expected_type == list:
                        _list_cast = ast.literal_eval(
                            self._data.decode("utf-8")
                            if isinstance(self._data, bytes)
                            else self._data
                        )
                        if isinstance(_list_cast, list):
                            return SocaResponse(success=True, message=_list_cast)
                        else:
                            return SocaError.CAST_ERROR(
                                helper=f"{self._data} seems to be a {type(self._data)} and not a list"
                            )

                    # All other types
                    else:
                        return SocaResponse(
                            success=True, message=expected_type(self._data)
                        )

                except Exception as e:
                    return SocaError.CAST_ERROR(
                        helper=f"Unable to cast {self._data} to {expected_type} due to {e}"
                    )

    def is_type(self, expected_type: Type):
        if isinstance(self._data, expected_type):
            return True
        else:
            return False

    def as_json(self):
        try:
            return SocaResponse(success=True, message=json.loads(self._data))
        except Exception as err:
            return SocaError.CAST_ERROR(
                helper=f"Unable to cast {self._data} as json due to {err}"
            )

    def as_yaml(self):
        try:
            return SocaResponse(success=True, message=yaml.safe_load(self._data))
        except Exception as err:
            return SocaError.CAST_ERROR(
                helper=f"Unable to cast {self._data} as YAML due to {err}"
            )

    def autocast(self, type_overrides: Dict[str, Type] = None, preserve_key_name: bool = False) -> dict:
        # This function will try to automatically cast self._data as its best type
        # Support nested list and dictionary
        _result = {}
        _cluster_id = f"/edh/{os.environ.get('EDH_CLUSTER_ID')}"
        logger.debug(
            f"Trying to autocast dictionary {self._data} with preserve_key_name to {preserve_key_name}"
        )

        if not preserve_key_name:
            if not isinstance(self._data, dict):
                return SocaError.CAST_ERROR(
                    helper=f"Data must be a dict when preserve_key_name is set to False"
                )

            _updated_dict = {}
            for key, value in self._data.items():
                _updated_dict[key.replace(_cluster_id, "")] = value
            self._data.clear()
            self._data.update(_updated_dict)

        try:
            _result = auto_cast(data=self._data, type_overrides=type_overrides)
            return SocaResponse(success=True, message=_result)

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.CAST_ERROR(
                helper=f"Unable to autocast {self._data} due to {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )


    def serialize_json(self, indent: int = 2):
        """
        Safely serialize any object (including custom classes, Enums, etc.) into JSON.
        Recursively converts attributes to make them JSON serializable.
        """
        def _make_serializable(obj):
            # Handle Enums
            if isinstance(obj, enum.Enum):
                return obj.value

            # Handle dicts
            elif isinstance(obj, dict):
                return {k: _make_serializable(v) for k, v in obj.items()}

            # Handle lists, tuples, sets
            elif isinstance(obj, (list, tuple, set)):
                return [_make_serializable(v) for v in obj]

            # Handle custom classes
            elif hasattr(obj, "__dict__"):
                return {k: _make_serializable(v) for k, v in obj.__dict__.items()}

            # Handle other primitive types (int, str, float, bool, None)
            else:
                return obj

        try:
            serializable_obj = _make_serializable(self._data)
            json_str = json.dumps(serializable_obj, indent=indent)
            return SocaResponse(success=True, message=json_str)
        except Exception as err:
            return SocaError.CAST_ERROR(
                helper=f"Unable to serialize {type(self._data)} to JSON due to {err}"
            )


def annotation_accepted_types(annotation: Any) -> set:
    """Flatten a type annotation into the set of concrete types it accepts."""
    _origin = get_origin(annotation)

    if _origin is Literal:
        return {type(_arg) for _arg in get_args(annotation)}

    if _origin is Union:
        _accepted = set()
        for _arg in get_args(annotation):
            _accepted |= annotation_accepted_types(_arg)
        return _accepted

    if _origin is not None:
        return {_origin}

    return {annotation}


def scalar_as_str(value: Any) -> str:
    """
    Render a JSON/YAML scalar as the text it was written as.

    bool must render lowercase: JSON spells the literals that way, so str(True)
    would rename a value the operator typed as "true". Floats are not round-trip
    safe (192.50 becomes "192.5").
    """
    if Validators.is_bool(value):
        return "true" if value else "false"
    return str(value)


def coerce_scalar_fields_to_str(model_cls: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Coerce bool/int/float to str for str-only fields, mutating and returning data.

    Scheduler JSON and YAML infer types from unquoted scalars, so an OpenPBS
    project named "192" arrives as an int and one named "true" as a bool, neither
    of which pydantic accepts for a str field. A field whose annotation also
    accepts the incoming scalar type is left alone.
    """
    if not Validators.is_dict(data):
        return data

    for _field_name, _field in model_cls.model_fields.items():
        if _field_name not in data:
            continue

        _value = data[_field_name]
        if _value is None or Validators.is_string(_value):
            continue

        _accepted = annotation_accepted_types(_field.annotation)
        if str not in _accepted:
            continue

        # Leave the value alone when the annotation already accepts its own scalar
        # type. Validators.is_int excludes bool, so these branches do not overlap.
        if Validators.is_bool(_value):
            if bool in _accepted:
                continue
        elif Validators.is_int(_value):
            if int in _accepted:
                continue
        elif Validators.is_float(_value):
            if float in _accepted:
                continue
        else:
            continue

        _coerced = scalar_as_str(_value)
        logger.debug(
            f"Coercing {model_cls.__name__}.{_field_name} from "
            f"{type(_value).__name__} {_value!r} to str {_coerced!r}"
        )
        data[_field_name] = _coerced

    return data
