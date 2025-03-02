#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities import models
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.advisory import import_advisory
from vulnerabilities.tests.pipelines import TestLogger

advisory_data1 = AdvisoryData(
    aliases=["CVE-2020-13371337"],
    summary="vulnerability description here",
    affected_packages=[
        AffectedPackage(
            package=PackageURL(type="pypi", name="dummy"),
            affected_version_range=VersionRange.from_string("vers:pypi/>=1.0.0|<=2.0.0"),
        )
    ],
    references=[Reference(url="https://example.com/with/more/info/CVE-2020-13371337")],
    date_published=timezone.now(),
    url="https://test.com",
)


def get_advisory1(created_by="test_pipeline", alias_suffix=""):
    """Create an test advisory with date_imported not set."""
    aliases = (
        [f"{advisory_data1.aliases[0]}{alias_suffix}"] if alias_suffix else advisory_data1.aliases
    )
    advisory = models.Advisory.objects.create(
        aliases=aliases,
        summary=advisory_data1.summary,
        affected_packages=[pkg.to_dict() for pkg in advisory_data1.affected_packages],
        references=[ref.to_dict() for ref in advisory_data1.references],
        url=advisory_data1.url,
        created_by=created_by,
        date_collected=timezone.now(),
    )
    models.Advisory.objects.filter(id=advisory.id).update(
        date_imported=timezone.make_aware(timezone.datetime(9999, 1, 1))
    )
    return models.Advisory.objects.get(id=advisory.id)


class TestVulnerableCodePipeline(TestCase):
    def test_on_failure(self):
        class TestPipeline(VulnerableCodePipeline):
            def __init__(self, test_logger):
                super().__init__()
                self.log = test_logger.write

            @classmethod
            def steps(cls):
                return (cls.step1,)

            def step1(self):
                raise Exception("Something went wrong!")

            def on_failure(self):
                self.log("Doing cleanup.")

        logger = TestLogger()
        pipeline = TestPipeline(test_logger=logger)

        pipeline.execute()
        log_result = logger.getvalue()

        self.assertIn("Pipeline failed", log_result)
        self.assertIn("Running [on_failure] tasks", log_result)


class TestVulnerableCodeBaseImporterPipeline(TestCase):
    @patch.object(
        VulnerableCodeBaseImporterPipeline,
        "collect_advisories",
        return_value=[advisory_data1],
    )
    @patch.object(
        VulnerableCodeBaseImporterPipeline,
        "advisories_count",
        return_value=1,
    )
    def test_collect_and_store_advisories(self, mock_advisories_count, mock_collect_advisories):
        self.assertEqual(0, models.Advisory.objects.count())

        base_pipeline = VulnerableCodeBaseImporterPipeline()
        base_pipeline.pipeline_id = "test_pipeline"

        base_pipeline.collect_and_store_advisories()

        mock_advisories_count.assert_called_once()
        mock_collect_advisories.assert_called_once()

        self.assertEqual(1, models.Advisory.objects.count())

    def test_import_new_advisories(self):
        """Test the process of importing a new advisory creates a vulnerability."""
        self.assertEqual(0, models.Vulnerability.objects.count())
        advisory = get_advisory1()

        import_advisory(advisory=advisory, pipeline_id="test_pipeline", confidence=100)

        self.assertEqual(1, models.Vulnerability.objects.count())

        advisory.refresh_from_db()
        self.assertLess(advisory.date_imported.year, 9000)

    def test_import_new_advisories_with_multiple_advisories(self):
        """Test importing multiple advisories creates multiple vulnerabilities."""

        self.assertEqual(0, models.Vulnerability.objects.count())

        advisory1 = get_advisory1(alias_suffix="-first")
        advisory2 = get_advisory1(created_by="other_pipeline", alias_suffix="-second")

        import_advisory(advisory=advisory1, pipeline_id="test_pipeline")
        import_advisory(advisory=advisory2, pipeline_id="other_pipeline")

        self.assertEqual(2, models.Vulnerability.objects.count())

    def test_import_advisory_idempotent(self):
        """Test importing same advisory multiple times only creates one vulnerability."""

        self.assertEqual(0, models.Vulnerability.objects.count())
        advisory = get_advisory1()

        import_advisory(advisory=advisory, pipeline_id="test_pipeline")
        self.assertEqual(1, models.Vulnerability.objects.count())

        import_advisory(advisory=advisory, pipeline_id="test_pipeline")
        self.assertEqual(1, models.Vulnerability.objects.count())
