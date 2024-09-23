# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities for CPU template related functionality."""

import json
from pathlib import Path

import pytest

from framework.properties import global_props
from framework.utils_cpuid import CpuModel, CpuVendor, get_cpu_vendor

# All existing CPU templates available on Intel
INTEL_TEMPLATES = ["C3", "T2", "T2CL", "T2S"]
# All existing CPU templates available on AMD
AMD_TEMPLATES = ["T2A"]
# All existing CPU templates available on ARM
ARM_TEMPLATES = ["V1N1"]


def get_supported_cpu_templates():
    """
    Return the list of CPU templates supported by the platform.
    """
    # pylint:disable=too-many-return-statements
    host_linux = global_props.host_linux_version_tpl

    match get_cpu_vendor(), global_props.cpu_codename:
        # T2CL template is only supported on Cascade Lake and newer CPUs.
        case CpuVendor.INTEL, CpuModel.INTEL_SKYLAKE:
            return sorted(set(INTEL_TEMPLATES) - set(["T2CL"]))
        case CpuVendor.INTEL, _:
            return INTEL_TEMPLATES
        case CpuVendor.AMD, _:
            return AMD_TEMPLATES
        case CpuVendor.ARM, CpuModel.ARM_NEOVERSE_V1 if host_linux >= (6, 1):
            return ARM_TEMPLATES
        case _:
            return []


SUPPORTED_CPU_TEMPLATES = get_supported_cpu_templates()

# Custom CPU templates for Aarch64 for testing
AARCH64_CUSTOM_CPU_TEMPLATES_G2 = ["v1n1"]
AARCH64_CUSTOM_CPU_TEMPLATES_G3 = [
    "aarch64_with_sve_and_pac",
    "v1n1",
]


def get_supported_custom_cpu_templates():
    """
    Return the list of custom CPU templates supported by the platform.
    """
    host_linux = global_props.host_linux_version_tpl

    match get_cpu_vendor(), global_props.cpu_codename:
        # T2CL template is only supported on Cascade Lake and newer CPUs.
        case CpuVendor.INTEL, CpuModel.INTEL_SKYLAKE:
            return set(INTEL_TEMPLATES) - {"T2CL"}
        case CpuVendor.INTEL, _:
            return INTEL_TEMPLATES
        case CpuVendor.AMD, _:
            return AMD_TEMPLATES
        case CpuVendor.ARM, CpuModel.ARM_NEOVERSE_N1 if host_linux >= (6, 1):
            return AARCH64_CUSTOM_CPU_TEMPLATES_G2
        case CpuVendor.ARM, CpuModel.ARM_NEOVERSE_V1 if host_linux >= (6, 1):
            return AARCH64_CUSTOM_CPU_TEMPLATES_G3
        case _:
            return []


def custom_cpu_templates_params():
    """Return Custom CPU templates as pytest parameters"""
    for name in sorted(get_supported_custom_cpu_templates()):
        tmpl = Path(f"./data/static_cpu_templates/{name.lower()}.json")
        yield pytest.param(
            {"name": name, "template": json.loads(tmpl.read_text("utf-8"))},
            id="custom_" + name,
        )


def static_cpu_templates_params():
    """Return Static CPU templates as pytest parameters"""
    for name in sorted(get_supported_cpu_templates()):
        yield pytest.param(name, id="static_" + name)
