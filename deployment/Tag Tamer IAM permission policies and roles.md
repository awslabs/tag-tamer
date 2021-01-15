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

#### IAM role trust policy

```
{
  "Version": "2012-10-17",
  "Statement": [
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