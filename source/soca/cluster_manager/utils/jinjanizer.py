# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from jinja2 import (
    FileSystemLoader,
    select_autoescape,
    TemplateError,
    TemplateSyntaxError,
)
from jinja2.sandbox import SandboxedEnvironment
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
from utils.aws.boto3_wrapper import get_boto
import logging
import os
import sys
import pathlib
from types import SimpleNamespace

logger = logging.getLogger("soca_logger")


def _finalize_canonical(value):
    # autocast() types vars so {% if %} works, but renders bool as Python
    # "True"/"False"; bootstrap shell/config consumers need lowercase, so
    # normalize bool OUTPUT here (identity checks leave int/None/str untouched).
    if value is True:
        return "true"
    if value is False:
        return "false"
    return value


class SocaJinja2Renderer:
    """
    Class for rendering Jinja2 templates from strings.
    """

    @staticmethod
    def validate_template(data: str):
        try:
            SandboxedEnvironment().parse(data)
            return SocaResponse(success=True, message="Template syntax is valid")
        except TemplateSyntaxError as err:
            return SocaError.JINJA_GENERATOR_ERROR(
                helper=f"Template syntax is invalid: {err}"
            )
        except Exception as err:
            return SocaError.JINJA_GENERATOR_ERROR(helper=f"{err}")

    @staticmethod
    def from_string(data: str, variables: dict):
        if not isinstance(variables, dict):
            return SocaError.JINJA_GENERATOR_ERROR(
                helper=f"Unable to cast {variables} as dict. Verify format"
            )
        try:
            template = SandboxedEnvironment().from_string(data)
            _rendered_user_data = template.render(**variables)
            return SocaResponse(success=True, message=_rendered_user_data)
        except TemplateSyntaxError as err:
            return SocaError.JINJA_GENERATOR_ERROR(
                helper=f"Your template syntax is invalid. Wrap your code inside raw/endraw if needed. Error: {err}"
            )
        except Exception as err:
            return SocaError.JINJA_GENERATOR_ERROR(helper=f"{err}")


class SocaJinja2Generator:
    """
    Class for rendering Jinja2 templates from template stored on local filesystem.
    """

    def __init__(self, get_template: str, variables: dict, template_dirs: list):
        self._get_template = get_template
        self._template_dirs = template_dirs
        self._variables = variables

    def build_jinja2_environment(self):
        _as_list = SocaCastEngine(data=self._template_dirs).cast_as(list)
        if _as_list.success is True:
            self._template_dirs = _as_list.message
        else:
            return SocaError.JINJA_GENERATOR_ERROR(
                helper=f"Unable to cast {self._template_dirs} as list. Verify format"
            )

        logger.debug(f"Jinja2 template dir: {self._template_dirs}")
        _jinja2_env = SandboxedEnvironment(
            loader=FileSystemLoader(self._template_dirs),
            extensions=["jinja2.ext.do"],
            finalize=_finalize_canonical,
            autoescape=select_autoescape(
                enabled_extensions=("j2", "jinja2"),
                default_for_string=True,
                default=True,
            ),
        )
        return _jinja2_env

    def to_stdout(self, autocast_values: bool = False):
        try:
            _j2_env = self.build_jinja2_environment()
            if autocast_values:
                _autocast = SocaCastEngine(data=self._variables).autocast()
                if _autocast.success:
                    self._variables = _autocast.message
                else:
                    return SocaError.JINJA_GENERATOR_ERROR(helper=_autocast.message)

            try:
                _rendered_template = _j2_env.get_template(self._get_template).render(
                    context=self._variables,
                    ns=SimpleNamespace(template_already_included=[]),
                )
            except TemplateError as err:
                logger.error(f"Unable to generate {self._get_template} due to {err} ")
                return SocaError.JINJA_GENERATOR_ERROR(helper=f"{err}")

            return SocaResponse(success=True, message=_rendered_template)
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.JINJA_GENERATOR_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )

    def to_s3(self, bucket_name: str, key: str, autocast_values: bool = False):
        try:
            _init_s3_client = get_boto(service_name="s3")
            if _init_s3_client.get("success") is False:
                return SocaError.JINJA_GENERATOR_ERROR(
                    helper=f"Unable to initialize s3 client because of {_init_s3_client.get('message')}"
                )
            else:
                _s3_client = _init_s3_client.get("message")

            _j2_env = self.build_jinja2_environment()
            if autocast_values:
                _autocast = SocaCastEngine(data=self._variables).autocast()
                if _autocast.success:
                    self._variables = _autocast.message
                else:
                    return SocaError.JINJA_GENERATOR_ERROR(helper=_autocast.message)

            try:
                _rendered_template = _j2_env.get_template(self._get_template).render(
                    context=self._variables,
                    ns=SimpleNamespace(template_already_included=[]),
                )
            except TemplateError as err:
                logger.error(f"Unable to generate {self._get_template} due to {err} ")
                return SocaError.JINJA_GENERATOR_ERROR(helper=f"{err}")

            try:
                _s3_client.put_object(
                    Bucket=bucket_name, Key=key, Body=_rendered_template
                )
            except Exception as err:
                return SocaError.JINJA_GENERATOR_ERROR(
                    helper=f"Unable to write rendered template to s3://{bucket_name}/{key} because of {err}"
                )

            return SocaResponse(
                success=True,
                message=f"Rendered template written to s3://{bucket_name}/{key}",
            )
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.JINJA_GENERATOR_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )

    def to_file(self, output_file_path: str, autocast_values: bool = False):
        try:
            logger.info("Checking if output_file_path is a valid location")
            _output_file = pathlib.Path(output_file_path)
            if str(_output_file.parent) != ".":
                if not _output_file.parent.exists:
                    return SocaError.GENERIC_ERROR(
                        helper=f"{_output_file.parent} does not seems to be a valid/writeable location"
                    )

            _j2_env = self.build_jinja2_environment()

            if autocast_values:
                _autocast = SocaCastEngine(data=self._variables).autocast()
                if _autocast.success:
                    self._variables = _autocast.message
                else:
                    return SocaError.JINJA_GENERATOR_ERROR(helper=_autocast.message)

            try:
                _rendered_template = _j2_env.get_template(self._get_template).render(
                    context=self._variables,
                    ns=SimpleNamespace(template_already_included=[]),
                )
            except TemplateError as err:
                logger.error(f"Unable to generate {self._get_template} due to {err} ")
                return SocaError.JINJA_GENERATOR_ERROR(helper=f"{err}")
            logger.info(f"Writing rendered template to {_output_file}")
            output_file = pathlib.Path(_output_file)
            if _output_file.exists():
                return SocaError.JINJA_GENERATOR_ERROR(
                    helper=f"{output_file} already exists"
                )
            else:
                output_file.write_text(_rendered_template)
                return SocaResponse(
                    success=True, message=f"Rendered template written to {_output_file}"
                )

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.JINJA_GENERATOR_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )
