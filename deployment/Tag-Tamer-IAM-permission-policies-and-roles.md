# Tag Tamer IAM permission policies & roles

## Tag Tamer AWS CloudFormation IAM permission policy to deploy Tag Tamer stack templates

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "TagTamerCFNPermissions",
            "Effect": "Allow",
            "Action": [
                "cognito-idp:CreateIdentityProvider",
                "cognito-idp:CreateGroup",
                "cognito-idp:CreateUserPool",
                "cognito-idp:CreateUserPoolClient",
                "cognito-idp:CreateUserPoolDomain",
                "cognito-idp:DeleteGroup",
                "cognito-idp:DeleteIdentityProvider",
                "cognito-idp:DeleteUserPool",
                "cognito-idp:DeleteUserPoolClient",
                "cognito-idp:DeleteUserPoolDomain",
                "dynamodb:CreateTable",
                "dynamodb:DescribeContinuousBackups",
                "dynamodb:DeleteTable",
                "dynamodb:DescribeTable",
                "ec2:AllocateAddress",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:CreateInternetGateway",
                "ec2:CreateNatGateway",
                "ec2:CreateRoute",
                "ec2:CreateSecurityGroup",
                "ec2:CreateSubnet",
                "ec2:CreateVpc",
                "ec2:CreateRouteTable",
                "ec2:CreateTags",
                "ec2:DeleteInternetGateway",
                "ec2:DeleteNatGateway",
                "ec2:DeleteKeyPair",
                "ec2:DeleteRoute",
                "ec2:DeleteRouteTable",
                "ec2:DeleteSecurityGroup",
                "ec2:DeleteSubnet",
                "ec2:DeleteTags",
                "ec2:DeleteVolume",
                "ec2:DeleteVpc",
                "ec2:DescribeAddresses",
                "ec2:DescribeImages",
                "ec2:DescribeInstances",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeKeyPairs",
                "ec2:DescribeRouteTables",
                "ec2:DescribeVolumes",
                "ec2:DescribeNatGateways",
                "ec2:DescribeVpcs",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeTags",
                "ec2:DetachVolume",
                "ec2:DisassociateRouteTable",
                "ec2:ModifyVpcAttribute",
                "ec2:ReleaseAddress",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:RunInstances",
                "ec2:TerminateInstances",
                "elasticloadbalancing:CreateListener",
                "elasticloadbalancing:CreateLoadBalancer",
                "elasticloadbalancing:CreateRule",
                "elasticloadbalancing:CreateTargetGroup",
                "elasticloadbalancing:DeleteListener",
                "elasticloadbalancing:DeleteLoadBalancer",
                "elasticloadbalancing:DeleteRule",
                "elasticloadbalancing:DeleteTargetGroup",
                "elasticloadbalancing:DeregisterTargets",
                "iam:CreateInstanceProfile",
                "iam:DeletePolicy",
                "iam:PassRole",
                "iam:DeleteInstanceProfile",
                "iam:DeleteRole",
                "iam:CreatePolicy",
                "iam:AddRoleToInstanceProfile",
                "iam:AttachRolePolicy",
                "iam:DetachRolePolicy",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:CreateRole",
                "iam:GetRole",
                "lambda:CreateFunction",
                "lambda:DeleteFunction",
                "lambda:InvokeFunction",
                "lambda:PublishVersion",
                "lambda:UpdateFunctionCode",
                "lambda:UpdateFunctionConfiguration",
                "ssm:AddTagsToResource",
                "ssm:DeleteParameter",
                "ssm:GetParameters",
                "ssm:DeleteParameters",
                "ssm:PutParameter",
                "wafv2:AssociateWebACL",
                "wafv2:CreateWebACL",
                "wafv2:DisassociateWebACL"
            ],
            "Resource": "*"
        }
    ]
}
```

## Tag Tamer web app Amazon EC2 instance profile

The Tag Tamer web app instance profile includes an inline IAM policy and AWS managed IAM policies, The inline policy and AWS managed IAM policies are shown in the following two subsections.

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

#### IAM role trust policy for Tag Tamer web app instance profile

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

## AWS IAM policy & role for tag-tamer-resource-auto-tagger AWS Lambda function

### IAM permission policy

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "TagTamerDynamoDBTables",
            "Effect": "Allow",
            "Action": "dynamodb:GetItem",
            "Resource": "arn:aws:dynamodb:*:*:table/tag_tamer_roles"
        },
        {
            "Sid": "TagTamerAutoTaggerPermissions",
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags",
                "ec2:DeleteTags",
                "ec2:DescribeInstances",
                "ec2:DescribeTags",
                "ec2:DescribeVolumes",
                "iam:ListPolicies",
                "iam:ListRoles",
                "iam:ListRolePolicies",
                "iam:ListRoleTags",
                "iam:TagRole",
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

## Example AWS IAM policies and roles for Cognito User Pool Groups

### Example IAM role permissions policy allowing Amazon Cognito User Pool Group to perform all Tag Tamer web app actions

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "TagTamerDynamoDBTables",
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
            "Sid": "TagTamerAllAdminPermissions",
            "Effect": "Allow",
            "Action": [
                "codecommit:GetRepository",
                "codecommit:ListRepositories",
                "codecommit:ListTagsForResource",
                "codecommit:TagResource",
                "codepipeline:ListPipelines",
                "codepipeline:GetPipeline",
                "codepipeline:TagResource",
                "codepipeline:ListTagsForResource",
                "config:DescribeConfigRules",
                "config:ListTagsForResource",
                "config:PutConfigRule",
                "config:TagResource",
                "config:UntagResource",
                "dynamodb:DescribeTable",
                "dynamodb:ListTables",
                "dynamodb:ListTagsOfResource",
                "dynamodb:TagResource",
                "dynamodb:UntagResource",
                "ec2:CreateTags",
                "ec2:DeleteTags",
                "ec2:DescribeInstances",
                "ec2:DescribeTags",
                "ec2:DescribeVolumes",
                "ecr:DescribeRepositories",
                "ecr:ListTagsForResource",
                "ecr:TagResource",
                "ecr:UntagResource",
                "ecs:DescribeClusters",
                "ecs:DescribeTasks",
                "ecs:DescribeTaskDefinition",
                "ecs:ListTagsForResource",
                "ecs:TagResource",
                "ecs:UntagResource",
                "eks:DescribeCluster",
                "eks:DescribeNodegroup",
                "eks:ListClusters",
                "eks:ListNodegroups",
                "eks:ListTagsForResource",
                "eks:TagResource",
                "eks:UntagResource",
                "iam:GetRole",
                "iam:ListPolicies",
                "iam:ListRoles",
                "iam:ListRolePolicies",
                "iam:ListRoleTags",
                "iam:TagRole",
                "iam:TagUser",
                "lambda:GetFunction",
                "lambda:ListFunctions",
                "lambda:ListTags",
                "lambda:TagResource",
                "rds:AddTagsToResource",
                "rds:DescribeDBClusters",
                "rds:DescribeDBClusterEndpoints",
                "rds:DescribeDBInstances",
                "rds:DescribeGlobalClusters",
                "rds:DescribeOptionGroups",
                "rds:ListTagsForResource",
                "rds:RemoveTagsFromResource",
                "redshift:CreateTags",
                "redshift:DeleteTags",
                "redshift:DescribeClusters",
                "s3:PutObjectTagging",
                "s3:DeleteObjectTagging",
                "s3:GetBucketTagging",
                "s3:GetObject",
                "s3:GetObjectTagging",
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:PutBucketTagging",
                "s3:ReplicateTags",
                "servicecatalog:AssociateTagOptionWithResource",
                "servicecatalog:CreateTagOption",
                "servicecatalog:DescribeProduct",
                "servicecatalog:DescribeProductAsAdmin",
                "servicecatalog:DeleteTagOption",
                "servicecatalog:DescribeTagOption",
                "servicecatalog:DisassociateTagOptionFromResource",
                "servicecatalog:ListTagsForResource",
                "servicecatalog:ListTagOptions",
                "servicecatalog:SearchProducts",
                "servicecatalog:SearchProductsAsAdmin",
                "servicecatalog:TagResource",
                "servicecatalog:UntagResource",
                "servicecatalog:UpdateTagOption",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

### Example IAM role permissions policy allowing user to perform all Tag Tamer web app actions except modify Tag Groups

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "TagTamerDynamoDBTables",
            "Effect": "Allow",
            "Action": [
                "dynamodb:GetItem",
                "dynamodb:Scan"
            ],
            "Resource": [
                "arn:aws:dynamodb:*:*:table/tag_tamer_roles",
                "arn:aws:dynamodb:*:*:table/tag_tamer_tag_groups"
            ]
        },
        {
            "Sid": "TagTamerAdminPermissionsLessChangeTags",
            "Effect": "Allow",
            "Action": [
                "codecommit:GetRepository",
                "codecommit:ListRepositories",
                "codecommit:ListTagsForResource",
                "codecommit:TagResource",
                "codepipeline:ListPipelines",
                "codepipeline:GetPipeline",
                "codepipeline:TagResource",
                "codepipeline:ListTagsForResource",
                "config:DescribeConfigRules",
                "config:ListTagsForResource",
                "config:PutConfigRule",
                "config:TagResource",
                "config:UntagResource",
                "dynamodb:DescribeTable",
                "dynamodb:ListTables",
                "dynamodb:ListTagsOfResource",
                "dynamodb:TagResource",
                "dynamodb:UntagResource",
                "ec2:CreateTags",
                "ec2:DeleteTags",
                "ec2:DescribeInstances",
                "ec2:DescribeTags",
                "ec2:DescribeVolumes",
                "ecr:DescribeRepositories",
                "ecr:ListTagsForResource",
                "ecr:TagResource",
                "ecr:UntagResource",
                "ecs:DescribeClusters,
                "ecs:DescribeTasks",
                "ecs:DescribeTaskDefinition",
                "ecs:ListTagsForResource",
                "ecs:TagResource",
                "ecs:UntagResource",
                "eks:DescribeCluster",
                "eks:DescribeNodegroup",
                "eks:ListClusters",
                "eks:ListNodegroups",
                "eks:ListTagsForResource",
                "eks:TagResource",
                "eks:UntagResource",
                "iam:GetRole",
                "iam:ListPolicies",
                "iam:ListRoles",
                "iam:ListRolePolicies",
                "iam:ListRoleTags",
                "iam:TagRole",
                "iam:TagUser",
                "lambda:GetFunction",
                "lambda:ListFunctions",
                "lambda:ListTags",
                "lambda:TagResource",
                "rds:AddTagsToResource",
                "rds:DescribeDBClusters",
                "rds:DescribeDBClusterEndpoints",
                "rds:DescribeDBInstances",
                "rds:DescribeGlobalClusters",
                "rds:DescribeOptionGroups",
                "rds:ListTagsForResource",
                "rds:RemoveTagsFromResource",
                "redshift:CreateTags",
                "redshift:DeleteTags",
                "redshift:DescribeClusters",
                "s3:PutObjectTagging",
                "s3:DeleteObjectTagging",
                "s3:GetBucketTagging",
                "s3:GetObject",
                "s3:GetObjectTagging",
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:PutBucketTagging",
                "s3:ReplicateTags",
                "servicecatalog:AssociateTagOptionWithResource",
                "servicecatalog:CreateTagOption",
                "servicecatalog:DescribeProduct",
                "servicecatalog:DescribeProductAsAdmin",
                "servicecatalog:DeleteTagOption",
                "servicecatalog:DescribeTagOption",
                "servicecatalog:DisassociateTagOptionFromResource",
                "servicecatalog:ListTagsForResource",
                "servicecatalog:ListTagOptions",
                "servicecatalog:SearchProducts",
                "servicecatalog:SearchProductsAsAdmin",
                "servicecatalog:TagResource",
                "servicecatalog:UntagResource",
                "servicecatalog:UpdateTagOption",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

### Example IAM role trust policy

- The base AWS account is were you deploy Tag Tamer using its AWS CloudFormation template. In this example, below, the base account is _111122223333_.
- Tag Tamer can manage resource tags in other linked AWS accounts. In this example, below, the linked account is _444455556666_.
- This IAM role trust policy in the _base AWS account_ must include the IAM role ARN for every linked AWS account. All IAM role ARN's must use identical IAM role names as shown in the example, below.
- Every linked AWS account must include its IAM role ARN and the IAM role ARN of the base AWS account.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::111122223333:role/DEMOTagTamerAllAdminActionsRole",
          "arn:aws:iam::444455556666:role/DEMOTagTamerAllAdminActionsRole"
        ]
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
