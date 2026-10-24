import builtins

import pytest

from security_engine import aws_assessment


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self):
        self.calls = []

    def list_buckets(self):
        self.calls.append(("list_buckets", {}))
        return {"Buckets": [{"Name": "public-bucket"}, {"Name": "private-bucket"}]}

    def get_bucket_policy_status(self, Bucket):
        self.calls.append(("get_bucket_policy_status", {"Bucket": Bucket}))
        if Bucket == "private-bucket":
            raise FakeClientError("NoSuchBucketPolicy")
        return {"PolicyStatus": {"IsPublic": True}}

    def get_public_access_block(self, Bucket):
        self.calls.append(("get_public_access_block", {"Bucket": Bucket}))
        if Bucket == "private-bucket":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        raise FakeClientError("NoSuchPublicAccessBlockConfiguration")

    def get_bucket_acl(self, Bucket):
        self.calls.append(("get_bucket_acl", {"Bucket": Bucket}))
        if Bucket == "public-bucket":
            return {
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": (
                                "http://acs.amazonaws.com/groups/global/AllUsers"
                            ),
                        },
                        "Permission": "READ",
                    }
                ]
            }
        return {"Grants": []}


class FakeEC2:
    def __init__(self):
        self.calls = []

    def describe_security_groups(self):
        self.calls.append(("describe_security_groups", {}))
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "IpPermissions": [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        },
                    ],
                },
                {
                    "GroupId": "sg-rdp",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        }
                    ],
                },
            ]
        }


class FakeCloudTrail:
    def __init__(self, trails=None, logging=True):
        self.trails = [
            {
                "Name": "organization-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org",
                "IsMultiRegionTrail": True,
            }
        ] if trails is None else trails
        self.logging = logging
        self.calls = []

    def describe_trails(self, includeShadowTrails):
        self.calls.append(("describe_trails", {"includeShadowTrails": includeShadowTrails}))
        return {"trailList": self.trails}

    def get_trail_status(self, Name):
        self.calls.append(("get_trail_status", {"Name": Name}))
        return {"IsLogging": self.logging}


class FakeSession:
    def __init__(self, cloudtrail=None):
        self.region_name = "us-east-1"
        self.s3 = FakeS3()
        self.ec2 = FakeEC2()
        self.cloudtrail = cloudtrail or FakeCloudTrail()
        self.clients = []

    def client(self, service_name, region_name):
        self.clients.append((service_name, region_name))
        return {
            "s3": self.s3,
            "ec2": self.ec2,
            "cloudtrail": self.cloudtrail,
        }[service_name]


def test_assessment_reports_public_s3_and_world_open_security_groups():
    session = FakeSession()
    result = aws_assessment._assess(
        session,
        (FakeClientError,),
        ["us-east-1"],
    )

    findings = result["findings"]
    assert result["status"] == "completed"
    assert result["total_findings"] == 6
    assert [finding["test_id"] for finding in findings] == [
        "AWS-S3-001",
        "AWS-S3-003",
        "AWS-S3-002",
        "AWS-EC2-001",
        "AWS-EC2-001",
        "AWS-EC2-001",
    ]
    assert {finding["language"] for finding in findings} == {"AWS"}
    assert all(finding["line_number"] is None for finding in findings)
    assert session.clients == [
        ("s3", "us-east-1"),
        ("ec2", "us-east-1"),
        ("cloudtrail", "us-east-1"),
    ]


def test_assessment_reports_missing_or_stopped_cloudtrail_coverage():
    session = FakeSession(cloudtrail=FakeCloudTrail(trails=[]))
    result = aws_assessment._assess(session, (FakeClientError,), ["us-east-1"])

    assert [finding["test_id"] for finding in result["findings"]] == [
        "AWS-S3-001",
        "AWS-S3-003",
        "AWS-S3-002",
        "AWS-EC2-001",
        "AWS-EC2-001",
        "AWS-EC2-001",
        "AWS-CT-001",
        "AWS-CT-003",
    ]

    stopped = FakeSession(cloudtrail=FakeCloudTrail(logging=False))
    stopped_result = aws_assessment._assess(
        stopped,
        (FakeClientError,),
        ["us-east-1"],
    )
    assert [finding["test_id"] for finding in stopped_result["findings"]][-2:] == [
        "AWS-CT-002",
        "AWS-CT-003",
    ]


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}, True),
        ({"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389}, True),
        ({"IpProtocol": "6", "FromPort": 22, "ToPort": 22}, True),
        ({"IpProtocol": 6, "FromPort": 3389, "ToPort": 3389}, True),
        ({"IpProtocol": "tcp", "FromPort": 20, "ToPort": 24}, True),
        ({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}, False),
        ({"IpProtocol": "udp", "FromPort": 22, "ToPort": 22}, False),
        ({"IpProtocol": "udp", "FromPort": 3389, "ToPort": 3389}, True),
        ({"IpProtocol": "17", "FromPort": 3389, "ToPort": 3389}, True),
        ({"IpProtocol": 17, "FromPort": 22, "ToPort": 3389}, True),
        ({"IpProtocol": "-1"}, True),
        ({"IpProtocol": -1}, True),
        ({"IpProtocol": "udp", "FromPort": 3000, "ToPort": 3400}, True),
        ({"IpProtocol": "icmp", "FromPort": 22, "ToPort": 22}, False),
        ({"IpProtocol": "not-a-protocol", "FromPort": 22, "ToPort": 22}, False),
        ({"IpProtocol": ["tcp"], "FromPort": 22, "ToPort": 22}, False),
        ({"IpProtocol": True, "FromPort": 22, "ToPort": 22}, False),
        (None, False),
        ({"IpProtocol": "tcp", "FromPort": 22}, False),
        ({"IpProtocol": "tcp", "FromPort": "22", "ToPort": 22}, False),
        ({"IpProtocol": "tcp", "FromPort": True, "ToPort": 22}, False),
        ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 65536}, False),
        ({"IpProtocol": "tcp", "FromPort": 3390, "ToPort": 3389}, False),
        ({"FromPort": 22, "ToPort": 22}, False),
    ],
)
def test_security_group_risk_requires_matching_protocol_and_valid_ports(rule, expected):
    assert aws_assessment._is_overly_permissive(rule) is expected


def test_security_group_rules_with_restricted_cidrs_are_not_reported():
    class RestrictedEC2:
        def describe_security_groups(self):
            return {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-private",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                            },
                            {
                                "IpProtocol": "-1",
                                "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}],
                            },
                        ],
                    }
                ]
            }

    class RestrictedSession:
        def client(self, service_name, region_name):
            assert service_name == "ec2"
            return RestrictedEC2()

    assert (
        aws_assessment._scan_security_groups(
            RestrictedSession(),
            (FakeClientError,),
            "us-east-1",
        )
        == []
    )


def test_assessment_surfaces_aws_permission_errors():
    class DeniedS3(FakeS3):
        def list_buckets(self):
            raise FakeClientError("AccessDenied")

    session = FakeSession()
    session.s3 = DeniedS3()

    with pytest.raises(aws_assessment.AwsAssessmentError, match="AccessDenied"):
        aws_assessment._assess(session, (FakeClientError,), ["us-east-1"])


def test_api_item_iterator_follows_pagination_tokens():
    class PagedClient:
        def __init__(self):
            self.tokens = []

        def list_items(self, NextToken=None):
            self.tokens.append(NextToken)
            if NextToken is None:
                return {"Items": ["first"], "NextToken": "page-two"}
            return {"Items": ["second"]}

    client = PagedClient()
    items = list(
        aws_assessment._iter_api_items(
            client,
            "list_items",
            "Items",
            "NextToken",
            "NextToken",
            (FakeClientError,),
        )
    )

    assert items == ["first", "second"]
    assert client.tokens == [None, "page-two"]


def test_aws_sdk_is_optional_until_assessment_is_requested(monkeypatch):
    original_import = builtins.__import__

    def import_without_aws_sdk(name, *args, **kwargs):
        if name == "boto3" or name.startswith("botocore"):
            raise ModuleNotFoundError("AWS SDK is not installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_aws_sdk)

    with pytest.raises(aws_assessment.AwsAssessmentError, match="optional dependencies"):
        aws_assessment.run_aws_assessment()


def test_run_aws_assessment_uses_requested_profile_and_regions(monkeypatch):
    session = FakeSession()
    options = []

    def create_session(**kwargs):
        options.append(kwargs)
        return session

    monkeypatch.setattr(
        aws_assessment,
        "_load_aws_sdk",
        lambda: (create_session, (FakeClientError,)),
    )

    result = aws_assessment.run_aws_assessment(
        profile_name="audit",
        regions=["us-east-1", "us-west-2"],
    )

    assert options == [{"profile_name": "audit"}]
    assert result["status"] == "completed"
    assert session.clients == [
        ("s3", "us-east-1"),
        ("ec2", "us-east-1"),
        ("cloudtrail", "us-east-1"),
        ("ec2", "us-west-2"),
        ("cloudtrail", "us-west-2"),
    ]


def test_run_aws_assessment_uses_default_credential_chain(monkeypatch):
    session = FakeSession()
    options = []

    def create_session(**kwargs):
        options.append(kwargs)
        return session

    monkeypatch.setattr(
        aws_assessment,
        "_load_aws_sdk",
        lambda: (create_session, (FakeClientError,)),
    )

    result = aws_assessment.run_aws_assessment()

    assert options == [{}]
    assert result["status"] == "completed"
    assert session.clients[0] == ("s3", "us-east-1")


def test_run_aws_assessment_requires_a_region_when_profile_has_no_default(monkeypatch):
    class NoRegionSession(FakeSession):
        def __init__(self):
            super().__init__()
            self.region_name = None

    monkeypatch.setattr(
        aws_assessment,
        "_load_aws_sdk",
        lambda: (lambda **_kwargs: NoRegionSession(), (FakeClientError,)),
    )

    with pytest.raises(aws_assessment.AwsAssessmentError, match="No AWS region"):
        aws_assessment.run_aws_assessment()
