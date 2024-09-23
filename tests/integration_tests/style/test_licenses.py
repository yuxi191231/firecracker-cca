# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests checking against the existence of licenses in each file."""

import datetime

from framework import utils_repo

AMAZON_COPYRIGHT_YEARS = range(2018, datetime.datetime.now().year + 1)
AMAZON_COPYRIGHT = (
    "Copyright {} Amazon.com, Inc. or its affiliates. All Rights Reserved."
)
AMAZON_LICENSE = "SPDX-License-Identifier: Apache-2.0"
CHROMIUM_COPYRIGHT = "Copyright 2017 The Chromium OS Authors. All rights reserved."
CHROMIUM_LICENSE = (
    "Use of this source code is governed by a BSD-style license that can be"
)
TUNTAP_COPYRIGHT = (
    "Copyright TUNTAP, 2017 The Chromium OS Authors. All rights reserved."
)
TUNTAP_LICENSE = (
    "Use of this source code is governed by a BSD-style license that can be"
)
ALIBABA_COPYRIGHT = "Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved."
ALIBABA_LICENSE = "SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause"
INTEL_COPYRIGHT = "Copyright © 2019 Intel Corporation"
INTEL_LICENSE = "SPDX-License-Identifier: Apache-2.0"
RIVOS_COPYRIGHT = "Copyright © 2023 Rivos, Inc."
RIVOS_LICENSE = "SPDX-License-Identifier: Apache-2.0"


def _has_amazon_copyright(string):
    for year in AMAZON_COPYRIGHT_YEARS:
        if AMAZON_COPYRIGHT.format(year) in string:
            return True
    return False


def _look_for_license(file, license_msg):
    line = file.readline()
    while line.startswith("//") or line.startswith("#"):
        if license_msg in line:
            return True
        line = file.readline()
    return False


def _validate_license(filename):
    """
    Validate license all .rs/.py. or .sh file.

    Python and Rust files should have the licenses on the first 2 lines
    Shell files license is located on lines 3-4 to account for shebang
    """
    with open(filename, "r", encoding="utf-8") as file:
        # Find the copyright line
        while True:
            line = file.readline()
            if line.startswith(("// Copyright", "# Copyright")):
                copyright_info = line
                break
            if line == "":
                return False

        has_amazon_copyright = _has_amazon_copyright(
            copyright_info
        ) and _look_for_license(file, AMAZON_LICENSE)

        has_chromium_copyright = (
            CHROMIUM_COPYRIGHT in copyright_info
            and _look_for_license(file, CHROMIUM_LICENSE)
        )

        has_tuntap_copyright = TUNTAP_COPYRIGHT in copyright_info and _look_for_license(
            file, CHROMIUM_LICENSE
        )

        has_alibaba_copyright = (
            ALIBABA_COPYRIGHT in copyright_info
            and _look_for_license(file, ALIBABA_LICENSE)
        )

        has_intel_copyright = INTEL_COPYRIGHT in copyright_info and _look_for_license(
            file, INTEL_LICENSE
        )

        has_rivos_copyright = RIVOS_COPYRIGHT in copyright_info and _look_for_license(
            file, RIVOS_LICENSE
        )

        return (
            has_amazon_copyright
            or has_chromium_copyright
            or has_tuntap_copyright
            or has_alibaba_copyright
            or has_intel_copyright
            or has_rivos_copyright
        )
    return True


def test_for_valid_licenses():
    """
    Test that all *.py, *.rs and *.sh files contain a valid license.
    """

    python_files = list(utils_repo.git_repo_files(root="..", glob="*.py"))
    rust_files = list(utils_repo.git_repo_files(root="..", glob="*.rs"))
    bash_files = list(utils_repo.git_repo_files(root="..", glob="*.sh"))
    c_files = list(utils_repo.git_repo_files(root="..", glob="*.c"))
    all_files = rust_files + python_files + bash_files + c_files
    error_msg = []
    for file in all_files:
        if _validate_license(file) is False:
            error_msg.append(file)
    assert not error_msg, f"Files {error_msg} have invalid licenses"


if __name__ == "__main__":
    test_for_valid_licenses()
