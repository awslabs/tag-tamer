# Tag Tamer IAM permission policies & roles

## Tag Tamer web app instance profile

### IAM Permission policy for instance profile IAM role

#### Inline Policies attached to instance profile IAM role
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "cognito-identity:GetId",
                "cognito-identity:GetCredentialsForIdentity"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "CognitoIdentity"
        },
        {
            "Action": [
                "ssm:GetParametersByPath"
            ],
            "Resource": "arn:aws:ssm:<YOUR_SSM_REGION>:<YOUR_AWS_ACCOUNT>:parameter/tag-tamer/*",
            "Effect": "Allow",
            "Sid": "SSMParameters"
        },
        {
            "Action": [
                "cognito-idp:AdminListGroupsForUser"
            ],
            "Resource": "arn:aws:cognito-idp:<YOUR_COGNITO_REGION>:<YOUR_AWS_ACCOUNT>:userpool/<YOUR_USER_POOL_ID>",
            "Effect": "Allow",
            "Sid": "CognitoUserPool"
        }
    ]
}
```
#### AWS managed policies attached to instance profile IAM role

```
arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

#### IAM role trust policy

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## role-based-tagger.py

### IAM permission policy

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "dynamodb:GetItem",
            "Resource": "arn:aws:dynamodb:*:*:table/tag_tamer_roles"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "iam:ListPolicies",
                "ec2:DescribeInstances",
                "iam:ListRoleTags",
                "ec2:DeleteTags",
                "ec2:DescribeTags",
                "ec2:CreateTags",
                "iam:TagRole",
                "ec2:DescribeVolumes",
                "iam:ListRoles",
                "iam:ListRolePolicies",
                "iam:TagUser"
            ],
            "Resource": "*"
        }
    ]
}
```

### IAM role trust policy

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Example Cognito User Pool Groups

### Example All access user pool group

#### IAM role permissions policy

```

    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}
```
### Example IAM role permissions policy allowing user to perform all Tag Tamer web app actions

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "dynamodb:PutItem",
                "dynamodb:GetItem",
                "dynamodb:Scan",
                "dynamodb:UpdateItem"
            ],
            "Resource": [
                "arn:aws:dynamodb:*:*:table/tag_tamer_roles",
                "arn:aws:dynamodb:*:*:table/tag_tamer_tag_groups"
            ]
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole",
                "lambda:TagResource",
                "ec2:DescribeInstances",
                "servicecatalog:SearchProducts",
                "iam:ListRoleTags",
                "eks:ListTagsForResource",
                "rds:DescribeGlobalClusters",
                "servicecatalog:UntagResource",
                "eks:DescribeNodegroup",
                "ec2:DescribeVolumes",
                "config:DescribeConfigRules",
                "s3:PutObjectTagging",
                "iam:ListRolePolicies",
                "servicecatalog:UpdateTagOption",
                "s3:DeleteObjectTagging",
                "iam:ListPolicies",
                "eks:ListNodegroups",
                "lambda:ListFunctions",
                "config:PutConfigRule",
                "ec2:CreateTags",
                "servicecatalog:ListTagsForResource",
                "s3:GetObject",
                "eks:DescribeCluster",
                "eks:ListClusters",
                "rds:RemoveTagsFromResource",
                "config:UntagResource",
                "rds:DescribeOptionGroups",
                "servicecatalog:DeleteTagOption",
                "s3:GetBucketTagging",
                "ec2:DeleteTags",
                "iam:TagRole",
                "s3:ReplicateTags",
                "s3:ListBucket",
                "servicecatalog:ListTagOptions",
                "s3:PutBucketTagging",
                "servicecatalog:DescribeTagOption",
                "lambda:ListTags",
                "servicecatalog:DescribeProduct",
                "rds:DescribeDBInstances",
                "s3:GetObjectTagging",
                "servicecatalog:AssociateTagOptionWithResource",
                "rds:AddTagsToResource",
                "servicecatalog:CreateTagOption",
                "eks:UntagResource",
                "ec2:DescribeTags",
                "lambda:GetFunction",
                "iam:ListRoles",
                "servicecatalog:TagResource",
                "iam:TagUser",
                "config:ListTagsForResource",
                "servicecatalog:SearchProductsAsAdmin",
                "servicecatalog:DescribeProductAsAdmin",
                "s3:ListAllMyBuckets",
                "rds:ListTagsForResource",
                "config:TagResource",
                "eks:TagResource",
                "rds:DescribeDBClusterEndpoints",
                "rds:DescribeDBClusters"
            ],
            "Resource": "*"
        }
    ]
}
```


#### Example IAM role trust policy

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/DEMOTagTamerAllAdminActionsRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity"
    }
  ]
}
```

