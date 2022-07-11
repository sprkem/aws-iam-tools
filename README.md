# AWS IAM Tools

This is a work in progress. Use at your own risk.

## Usage

```
python setup.py install
```

Then

```
ait search -p iam:PassRole -p iam:CreateRole
```

You can use also a credentials profile:

```
ait search -p iam:PassRole -p access-analyzer:ListAnalyzers --profile myProfile
```

By default output is in PrettyTable format, but you can specify either `PrettyTable` or `csv`:

```
ait search -p iam:PassRole -p iam:CreateRole --output csv
```