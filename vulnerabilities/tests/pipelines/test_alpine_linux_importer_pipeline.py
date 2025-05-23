#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from pathlib import Path

import pytest
from packageurl import PackageURL
from univers.versions import AlpineLinuxVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.pipelines.alpine_linux_importer import fetch_advisory_directory_links
from vulnerabilities.pipelines.alpine_linux_importer import fetch_advisory_links
from vulnerabilities.pipelines.alpine_linux_importer import load_advisories
from vulnerabilities.pipelines.alpine_linux_importer import process_record
from vulnerabilities.references import XsaReference
from vulnerabilities.tests.pipelines import TestLogger

TEST_DATA = Path(__file__).parent.parent / "test_data" / "alpine"


def test_process_record():
    logger = TestLogger()
    expected_advisories = [
        AdvisoryData(
            aliases=["XSA-248"],
            summary="",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={
                            "arch": "aarch64",
                            "distroversion": "v3.11",
                            "reponame": "main",
                        },
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r1"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "armhf", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r1"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "armv7", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r1"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={
                            "arch": "ppc64le",
                            "distroversion": "v3.11",
                            "reponame": "main",
                        },
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r1"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "s390x", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r1"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "x86", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r1"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r1"),
                ),
            ],
            references=[
                XsaReference(
                    reference_id="XSA-248",
                    url="https://xenbits.xen.org/xsa/advisory-248.html",
                    severities=[],
                )
            ],
            date_published=None,
            url="https://secdb.alpinelinux.org/v3.11/",
        ),
        AdvisoryData(
            aliases=["CVE-2018-7540", "XSA-252"],
            summary="",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={
                            "arch": "aarch64",
                            "distroversion": "v3.11",
                            "reponame": "main",
                        },
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r2"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "armhf", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r2"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "armv7", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r2"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={
                            "arch": "ppc64le",
                            "distroversion": "v3.11",
                            "reponame": "main",
                        },
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r2"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "s390x", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r2"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "x86", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r2"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="xen",
                        version=None,
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="4.10.0-r2"),
                ),
            ],
            references=[
                XsaReference(
                    reference_id="XSA-252",
                    url="https://xenbits.xen.org/xsa/advisory-252.html",
                    severities=[],
                )
            ],
            date_published=None,
            url="https://secdb.alpinelinux.org/v3.11/",
        ),
        AdvisoryData(
            aliases=["CVE-2017-9669"],
            summary="",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={
                            "arch": "aarch64",
                            "distroversion": "v3.11",
                            "reponame": "main",
                        },
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "armhf", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "armv7", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={
                            "arch": "ppc64le",
                            "distroversion": "v3.11",
                            "reponame": "main",
                        },
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "s390x", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "x86", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
            ],
            references=[],
            date_published=None,
            url="https://secdb.alpinelinux.org/v3.11/",
        ),
        AdvisoryData(
            aliases=["CVE-2017-9671"],
            summary="",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={
                            "arch": "aarch64",
                            "distroversion": "v3.11",
                            "reponame": "main",
                        },
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "armhf", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "armv7", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={
                            "arch": "ppc64le",
                            "distroversion": "v3.11",
                            "reponame": "main",
                        },
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "s390x", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "x86", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
                AffectedPackage(
                    package=PackageURL(
                        type="apk",
                        namespace="alpine",
                        name="apk-tools",
                        version=None,
                        qualifiers={"arch": "x86_64", "distroversion": "v3.11", "reponame": "main"},
                        subpath=None,
                    ),
                    affected_version_range=None,
                    fixed_version=AlpineLinuxVersion(string="2.7.2-r0"),
                ),
            ],
            references=[],
            date_published=None,
            url="https://secdb.alpinelinux.org/v3.11/",
        ),
    ]
    with open(TEST_DATA / "v3.11/main.json") as f:
        found_advisories = list(
            process_record(
                json.loads(f.read()),
                "https://secdb.alpinelinux.org/v3.11/",
                logger=logger.write,
            )
        )
        assert found_advisories == expected_advisories
    assert (
        "'4.10-1-r1' is not a valid AlpineVersion InvalidVersion(\"'4.10-1-r1' is not a valid <class 'univers.versions.AlpineLinuxVersion'>\")"
        in logger.getvalue()
    )


def test_fetch_advisory_directory_links():
    expected = [
        "https://secdb.alpinelinux.org/edge/",
        "https://secdb.alpinelinux.org/v3.10/",
        "https://secdb.alpinelinux.org/v3.11/",
        "https://secdb.alpinelinux.org/v3.12/",
        "https://secdb.alpinelinux.org/v3.13/",
        "https://secdb.alpinelinux.org/v3.14/",
        "https://secdb.alpinelinux.org/v3.15/",
        "https://secdb.alpinelinux.org/v3.2/",
        "https://secdb.alpinelinux.org/v3.3/",
        "https://secdb.alpinelinux.org/v3.4/",
        "https://secdb.alpinelinux.org/v3.5/",
        "https://secdb.alpinelinux.org/v3.6/",
        "https://secdb.alpinelinux.org/v3.7/",
        "https://secdb.alpinelinux.org/v3.8/",
        "https://secdb.alpinelinux.org/v3.9/",
    ]
    with open(TEST_DATA / "web_pages/directory.html") as f:
        assert (
            fetch_advisory_directory_links(f.read(), "https://secdb.alpinelinux.org/") == expected
        )


def test_fetch_advisory_directory_links_failure():
    logger = TestLogger()
    with open(TEST_DATA / "web_pages/fail_directory.html") as f:
        assert (
            fetch_advisory_directory_links(
                f.read(), "https://secdb.alpinelinux.org/", logger=logger.write
            )
            == []
        )
        assert "No versions found in 'https://secdb.alpinelinux.org/'" in logger.getvalue()


def test_fetch_advisory_links():
    expected = [
        "https://secdb.alpinelinux.org/v3.11/community.json",
        "https://secdb.alpinelinux.org/v3.11/main.json",
    ]
    with open(TEST_DATA / "web_pages/v3.11.html") as f:
        assert (
            list(fetch_advisory_links(f.read(), "https://secdb.alpinelinux.org/v3.11/")) == expected
        )


def test_fetch_advisory_links_failure():
    logger = TestLogger()
    with open(TEST_DATA / "web_pages/fail_directory.html") as f:
        assert list(fetch_advisory_links(f.read(), "v3.11", logger=logger.write)) == []
        assert "No anchor tags found in 'v3.11'" in logger.getvalue()


def test_process_record_without_packages():
    logger = TestLogger()
    with open(TEST_DATA / TEST_DATA / "v3.3/community.json") as f:
        assert list(process_record(json.loads(f.read()), "", logger=logger.write)) == []
        assert (
            "\"packages\" not found in this record {'apkurl': '{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk', 'archs': ['armhf', 'x86', 'x86_64'], 'reponame': 'community', 'urlprefix': 'https://dl-cdn.alpinelinux.org/alpine', 'distroversion': 'v3.3', 'packages': []}"
            in logger.getvalue()
        )


def test_load_advisories_package_without_name():
    logger = TestLogger()
    package = {
        "secfixes": {"4.10.0-r1": ["XSA-248"], "4.10.0-r2": ["CVE-2018-7540 XSA-252"]},
    }
    list(load_advisories(package, "v3.11", "main", archs=[], url="", logger=logger.write))
    assert (
        "\"name\" is not available in package {'secfixes': {'4.10.0-r1': ['XSA-248'], '4.10.0-r2': ['CVE-2018-7540 XSA-252']}}"
        in logger.getvalue()
    )


def test_load_advisories_package_without_secfixes():
    logger = TestLogger()
    package = {
        "name": "xen",
        "secfixes": {"4.10.0-r1": []},
    }
    list(load_advisories(package, "v3.11", "main", archs=[], url="", logger=logger.write))
    assert "No fixed vulnerabilities in version '4.10.0-r1'" in logger.getvalue()


@pytest.mark.parametrize(
    "test_case",
    [
        # these are the tests are not supported yet
        # when we start supporting these version,
        # they will be moved back to main test suite
        "1.9.5p2-r0",
        "6.6.2p1-r0",
        "6.6.4p1-r1",
        "4.10-1-r1",
    ],
)
def test_load_advisories_package_with_invalid_alpine_version(test_case):
    logger = TestLogger()
    package = {
        "name": "xen",
        "secfixes": {f"{test_case}": ["XSA-248"]},
    }
    list(load_advisories(package, "v3.11", "main", archs=[], url="", logger=logger.write))
    assert (
        f"{test_case!r} is not a valid AlpineVersion InvalidVersion(\"{test_case!r} is not a valid <class 'univers.versions.AlpineLinuxVersion'>\")"
        in logger.getvalue()
    )
