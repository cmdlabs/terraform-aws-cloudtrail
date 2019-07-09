resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = "${aws_s3_bucket.main.id}"
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = "${aws_kms_key.cloudtrail.arn}"
  event_selector {
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

data "aws_caller_identity" "audit" {
  provider = aws.audit
}

data "terraform_remote_state" "globals" {
  backend   = "s3"
  workspace = "global"
  config = {
    bucket  = "${var.global_state_bucket}"
    key     = "${var.global_state_key}"
    region  = "${var.global_state_region}"
    profile = "${var.global_state_profile}"
  }
}

resource "aws_kms_key" "cloudtrail" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "key-CLOUDTRAIL",
  "Statement": [
    {
      "Sid": "Allow administration of the key",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${data.aws_caller_identity.audit.account_id}:role/${var.client_name}-role-console-breakglass",
          "arn:aws:iam::${data.aws_caller_identity.audit.account_id}:role/${var.client_name}-role-api-fulladmin",
          "arn:aws:iam::${data.aws_caller_identity.audit.account_id}:role/${var.client_name}-role-api-secadmin"
        ]
      },
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:TagResource",
        "kms:UntagResource"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Allow use of the key",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${data.aws_caller_identity.audit.account_id}:role/${var.client_name}-role-api-secadmin"
        ]
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Action": "kms:GenerateDataKey*",
      "Condition": {
        "ForAllValues:StringLike": {
          "kms": ${jsonencode([for id in data.terraform_remote_state.globals.outputs.aws_account_ids : join("", ["arn:aws:cloudtrail:*:", id, ":trail/*"])])}
        }
      },
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "cloudtrail.amazonaws.com"
        ]
      },
      "Resource": "*",
      "Sid": "CloudTrailLogEncryption"
    },
    {
      "Sid": "AllowExternalAccountAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${data.terraform_remote_state.globals.outputs.aws_account_ids.master}:root"
        ]
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowExternalAccountsToAttachPersistentResources",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${data.terraform_remote_state.globals.outputs.aws_account_ids.master}:root"
        ]
      },
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "kms:GrantIsForAWSResource": true
        }
      }
    }
  ]
}
POLICY
}

resource "aws_kms_key" "s3" {
}

resource "aws_s3_bucket" "main" {
  provider = aws.audit

  bucket = "s3-${var.client_name}-cloudtrail"
  force_destroy = true
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.s3.arn}"
        sse_algorithm = "aws:kms"
      }
    }
  }
  object_lock_configuration {
    object_lock_enabled = "Enabled"
  }

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::s3-${var.client_name}-cloudtrail"
        },
        {
            "Sid": "AWSCloudTrailBucketDelivery",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": [
                "arn:aws:s3:::s3-${var.client_name}-cloudtrail/AWSLogs/*"
            ],
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
        {
            "Sid": "DenyNonSecureTransport",
            "Action": "s3:*",
            "Effect": "Deny",
            "Principal": "*",
            "Resource": "arn:aws:s3::s3-${var.client_name}-cloudtrail/*",
            "Condition": {"Bool": {"aws:SecureTransport": false}}
        },
        {
            "Sid": "AWSCloudTrailRead",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:ListBucket",
                "s3:ListBucketVersions"
            ],
            "Effect": "Allow",
            "Principal": {
                "AWS":
                    [
                        "arn:aws:iam::${data.aws_caller_identity.audit.account_id}:root"
                    ]
            },
            "Resource": [
                "arn:aws:s3::s3-${var.client_name}-cloudtrail/*",
                "arn:aws:s3::s3-${var.client_name}-cloudtrail"
            ],
            "Condition": {"Bool": {"aws:SecureTransport": false}}
        }
    ]
}
POLICY
}
