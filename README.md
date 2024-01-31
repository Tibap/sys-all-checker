# sys-all-checker

Script to check your GKE clusters against the Sys:All loophole / misconfiguration.

Original article from Orca Security: https://orca.security/resources/blog/sys-all-google-kubernetes-engine-risk

## How-to

* Authenticate to GCP: `gcloud auth application-default login`
* Create virtualenv: `python3 -m venv .venv`
* Activate virtual env: `source .venv/bin/activate`
* Install requirements: `pip install -r requirements.txt`
* Run script: `python3 sys-all-checker.py`

## Required role

Required roles: `roles/container.clusterViewer` at the organization level
