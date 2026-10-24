"""Read-only AWS security assessment."""

import argparse
import json
import sys


class AwsAssessmentError(Exception):
    """Raised when the AWS assessment cannot run reliably."""


def _load_aws_sdk():
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as error:
        raise AwsAssessmentError(
            "AWS support requires the optional dependencies. Install "
            "backend\\requirements-aws.txt and retry."
        ) from error

    return boto3.Session, (BotoCoreError, ClientError)


def _api_call(client, operation, errors, expected_errors=(), **kwargs):
    try:
        return getattr(client, operation)(**kwargs)
    except errors as error:
        response = getattr(error, "response", {})
        details = response.get("Error", {}) if isinstance(response, dict) else {}
        code = details.get("Code") if isinstance(details, dict) else None
        if code in expected_errors:
            return None
        message = f"AWS {operation} failed"
        if code:
            message += f" ({code})"
        raise AwsAssessmentError(f"{message}: {error}") from error


def _iter_api_items(
    client,
    operation,
    result_key,
    response_token,
    request_token,
    errors,
    **kwargs,
):
    token = None
    seen_tokens = set()
    while True:
        parameters = dict(kwargs)
        if token:
            parameters[request_token] = token
        response = _api_call(client, operation, errors, **parameters)
        items = response.get(result_key, [])
        if not isinstance(items, list):
            raise AwsAssessmentError(
                f"AWS {operation} returned invalid {result_key} data."
            )
        yield from items

        next_token = response.get(response_token)
        if not next_token:
            return
        if next_token in seen_tokens:
            raise AwsAssessmentError(f"AWS {operation} repeated a pagination token.")
        seen_tokens.add(next_token)
        token = next_token


def _finding(test_id, severity, filename, description, resource, region=None):
    finding = {
        "severity": severity,
        "confidence": "HIGH",
        "test_id": test_id,
        "language": "AWS",
        "filename": filename,
        "line_number": None,
        "description": description,
        "scanner": "AWS",
        "resource": resource,
    }
    if region:
        finding["region"] = region
    return finding


def _public_grants(acl):
    public_uris = {
        "http://acs.amazonaws.com/groups/global/AllUsers": "public",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": (
            "authenticated AWS users"
        ),
    }
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI")
        if uri in public_uris:
            yield public_uris[uri], grant.get("Permission", "unknown")


def _scan_s3(session, errors, region):
    client = session.client("s3", region_name=region)
    findings = []

    buckets = _iter_api_items(
        client,
        "list_buckets",
        "Buckets",
        "ContinuationToken",
        "ContinuationToken",
        errors,
    )
    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            raise AwsAssessmentError("S3 ListBuckets returned a bucket without a name.")

        policy = _api_call(
            client,
            "get_bucket_policy_status",
            errors,
            expected_errors=("NoSuchBucketPolicy",),
            Bucket=name,
        )
        if policy and policy.get("PolicyStatus", {}).get("IsPublic"):
            findings.append(
                _finding(
                    "AWS-S3-001",
                    "HIGH",
                    f"s3://{name}",
                    "Bucket policy is classified as public.",
                    name,
                )
            )

        public_access_block = _api_call(
            client,
            "get_public_access_block",
            errors,
            expected_errors=("NoSuchPublicAccessBlockConfiguration",),
            Bucket=name,
        )
        block_settings = (
            public_access_block.get("PublicAccessBlockConfiguration", {})
            if public_access_block
            else {}
        )
        block_options = (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
        if not all(block_settings.get(option) is True for option in block_options):
            findings.append(
                _finding(
                    "AWS-S3-003",
                    "MEDIUM",
                    f"s3://{name}",
                    "Bucket public access block is missing or incomplete.",
                    name,
                )
            )

        acl = _api_call(client, "get_bucket_acl", errors, Bucket=name)
        for principal, permission in _public_grants(acl):
            findings.append(
                _finding(
                    "AWS-S3-002",
                    "HIGH",
                    f"s3://{name}",
                    f"Bucket ACL grants {permission} access to {principal}. "
                    "Account- or bucket-level public access blocks may affect "
                    "effective access.",
                    name,
                )
            )
    return findings


def _world_cidrs(permission):
    for item in permission.get("IpRanges", []):
        if item.get("CidrIp") == "0.0.0.0/0":
            yield item["CidrIp"]
    for item in permission.get("Ipv6Ranges", []):
        if item.get("CidrIpv6") == "::/0":
            yield item["CidrIpv6"]


def _security_protocol(value):
    if isinstance(value, str):
        value = value.strip().lower()
        if value == "-1":
            return "all"
        if value in {"tcp", "udp"}:
            return value
        if value.isdecimal():
            value = int(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return {-1: "all", 6: "tcp", 17: "udp"}.get(value)
    return None


def _is_overly_permissive(permission):
    if not isinstance(permission, dict):
        return False
    protocol = _security_protocol(permission.get("IpProtocol"))
    if protocol == "all":
        return True
    if protocol not in {"tcp", "udp"}:
        return False

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if (
        not isinstance(from_port, int)
        or isinstance(from_port, bool)
        or not isinstance(to_port, int)
        or isinstance(to_port, bool)
        or from_port < 0
        or to_port > 65535
        or to_port < from_port
    ):
        return False

    sensitive_ports = (22, 3389) if protocol == "tcp" else (3389,)
    return any(from_port <= port <= to_port for port in sensitive_ports)


def _scan_security_groups(session, errors, region):
    client = session.client("ec2", region_name=region)
    findings = []

    groups = _iter_api_items(
        client,
        "describe_security_groups",
        "SecurityGroups",
        "NextToken",
        "NextToken",
        errors,
    )
    for group in groups:
        group_id = group.get("GroupId")
        if not group_id:
            raise AwsAssessmentError(
                f"EC2 DescribeSecurityGroups returned a group without an ID in {region}."
            )
        for permission in group.get("IpPermissions", []):
            if not _is_overly_permissive(permission):
                continue
            protocol = permission.get("IpProtocol", "unknown")
            for cidr in _world_cidrs(permission):
                findings.append(
                    _finding(
                        "AWS-EC2-001",
                        "HIGH",
                        f"aws://ec2/{region}/security-group/{group_id}",
                        f"Security group {group_id} allows protocol {protocol} "
                        f"from {cidr}; the rule exposes all traffic or SSH/RDP.",
                        group_id,
                        region,
                    )
                )
    return findings


def _scan_cloudtrail(session, errors, region):
    client = session.client("cloudtrail", region_name=region)
    trails = list(
        _iter_api_items(
            client,
            "describe_trails",
            "trailList",
            "NextToken",
            "NextToken",
            errors,
            includeShadowTrails=True,
        )
    )
    findings = []

    if not trails:
        findings.append(
            _finding(
                "AWS-CT-001",
                "HIGH",
                f"aws://cloudtrail/{region}",
                f"No CloudTrail trail was found for region {region}.",
                f"cloudtrail/{region}",
                region,
            )
        )
        return findings, False

    active_multi_region = False
    for trail in trails:
        trail_name = trail.get("TrailARN") or trail.get("Name")
        if not trail_name:
            raise AwsAssessmentError(
                f"CloudTrail DescribeTrails returned a trail without a name in {region}."
            )
        status = _api_call(
            client,
            "get_trail_status",
            errors,
            Name=trail_name,
        )
        logging = bool(status and status.get("IsLogging"))
        multi_region = bool(trail.get("IsMultiRegionTrail"))
        if logging and multi_region:
            active_multi_region = True
        if not logging:
            findings.append(
                _finding(
                    "AWS-CT-002",
                    "HIGH",
                    f"aws://cloudtrail/{region}/{trail_name}",
                    f"CloudTrail trail {trail_name} is not logging.",
                    trail_name,
                    region,
                )
            )

    return findings, active_multi_region


def _assess(session, errors, regions):
    selected_regions = list(dict.fromkeys(regions))
    if not selected_regions or any(not region for region in selected_regions):
        raise AwsAssessmentError("Specify at least one non-empty AWS region.")

    findings = _scan_s3(session, errors, selected_regions[0])
    active_multi_region_trail = False
    for region in selected_regions:
        findings.extend(_scan_security_groups(session, errors, region))
        cloudtrail_findings, active_trail = _scan_cloudtrail(
            session,
            errors,
            region,
        )
        findings.extend(cloudtrail_findings)
        active_multi_region_trail = active_multi_region_trail or active_trail

    if not active_multi_region_trail:
        findings.append(
            _finding(
                "AWS-CT-003",
                "HIGH",
                "aws://cloudtrail",
                "No active multi-region CloudTrail trail was found in the "
                "selected region set.",
                "cloudtrail",
            )
        )

    return {
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings,
    }


def run_aws_assessment(profile_name=None, regions=None):
    """Assess selected AWS resources using read-only APIs."""
    session_factory, errors = _load_aws_sdk()
    session_options = {"profile_name": profile_name} if profile_name else {}
    try:
        session = session_factory(**session_options)
    except errors as error:
        raise AwsAssessmentError(
            f"Could not initialize AWS session: {error}"
        ) from error
    selected_regions = list(regions or [])
    if not selected_regions:
        if not session.region_name:
            raise AwsAssessmentError(
                "No AWS region is configured. Pass --region or configure a "
                "default region in the selected profile."
            )
        selected_regions = [session.region_name]
    return _assess(session, errors, selected_regions)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        help="AWS profile name; defaults to the credential chain.",
    )
    parser.add_argument(
        "--region",
        action="append",
        dest="regions",
        help="Region to assess; repeat for multiple regions. Defaults to the profile region.",
    )
    args = parser.parse_args(argv)

    try:
        result = run_aws_assessment(args.profile, args.regions)
    except AwsAssessmentError as error:
        print(f"AWS assessment error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
