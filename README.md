# sys-all-checker

Script to check your GKE clusters against the Sys:All loophole / misconfiguration.

Original article from Orca Security: https://orca.security/resources/blog/sys-all-google-kubernetes-engine-risk

## How-to

* Create virtualenv: `python3 -m venv .venv`
* Activate virtual env: `source .venv/bin/activate`
* Install requirements: `pip install -r requirements.txt`
* Authenticate to GCP: `gcloud auth application-default login`
* Run script: `python3 sys-all-checker.py`
* Check output and results in output.csv (file is not created if no result are found)

Example output:

```
INFO:sys-all-checker:Authenticating to GCP
INFO:sys-all-checker:Looping through projects you have access to
INFO:sys-all-checker:Checking cluster: REDACTED in project id: REDACTED
[...]
INFO:sys-all-checker:!! ClusterRoleBinding 'TEST-RBAC' binds ClusterRole 'view' to 'system:authenticated'
[...]
INFO:sys-all-checker:Scanned xxx projects with a total of yyy clusters
INFO:sys-all-checker:Found 1 dangerous bindings
INFO:sys-all-checker:Check file 'output.csv' for results exported as CSV
```

## Required roles

* To list folders and projects in the organization: `roles/resourcemanager.folderViewer`
* To list clusters: `roles/container.clusterViewer` at the organization level
