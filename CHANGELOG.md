# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2021-04-01

### Added

- First Release Tag Tamer release
- Automatically tag AWS resources with your required tags – Tag Tamer applies your organization’s required resource tags when resources are created. Users no longer have to remember to enter your organization's required tags.
- Central source of tag truth - Infrastructure administrators no longer need to maintain and distribute separate lists or spreadsheets of approved tags. Tag Tamer stores your required tag options securely at rest in DynamoDB. Tag Tamer queries this database whenever it performs tagging actions.
- Prevent tag misspellings and capitalization errors – Tag Tamer performs all tagging actions using your approved required tags stored in DynamoDB so auto-tagging actions, Config Rule checks and tags selected for Service Catalog products employ your required tag options avoiding or repairing spelling and capitalization errors.
- Enforce tagging – Tag Tamer applies your required resource tags to AWS Config Rules in your AWS accounts. These AWS Config rules evaluate your AWS resources against your required tags and invoke your chosen remediation action when resources do not have proper required tags.
- Find incorrect tags & update – Tag Tamer finds and displays all existing AWS resources and their assigned tags so you can spot tagging inaccuracies then update AWS resources using your required tags via the Tag Tamer web user interface.
- Find untagged resources – The Tag Tamer web user interface reports untagged resources by service type. Tag Tamer groups those reported, untagged resources by AWS account and region.
- Export AWS resources and their assigned resource tags – Tag Tamer enables resource filtering by tag and value combination including untagged resources. You may export found resources and their currently assigned resources tags as CSV files using the Tag Tamer web user interface.
- Manage AWS Service Catalog’s TagOptions – Identify your organization’s required resource tag key and values within Tag Tamer then use Tag Tamer to update the tagging options in AWS Service Catalog so AWS Service Catalog users launch new product instances with your required tags applied.

### Changed

### Removed
