Install

```
pip install .
```

Then run with some permissions to search for e.g.

```
ait search -p iam:PassRole -p iam:CreateRole
```

Results are shown in table format, with a table for each permission specified.

Note: This is a work in progress and should not be considered complete. Results do not account for Service control policies or Permission boundaries.