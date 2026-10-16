#!/usr/bin/env python3
"""Find trusted original candidate evidence before permitting any rebuild."""
import json
import os
from pathlib import Path
import subprocess

from oci import Registry
from release import GitHubCompletion, admit, evidence


def api(endpoint):
    return json.loads(subprocess.check_output(['gh','api',endpoint],text=True))


def original_artifact(repository, name, revision):
    page=1
    while True:
        artifacts=api(f'repos/{repository}/actions/artifacts?name={name}&per_page=100&page={page}')['artifacts']
        for artifact in artifacts:
            if artifact['expired'] or artifact['name']!=name:
                continue
            run=api(f'repos/{repository}/actions/runs/{artifact["workflow_run"]["id"]}')
            if (run['event']=='push' and run['head_sha']==revision
                    and run['path']=='.github/workflows/distribution.yml'
                    and run['head_repository']['full_name']==repository):
                return artifact['workflow_run']['id']
        if len(artifacts)<100:
            return None
        page+=1


if __name__=='__main__':
    repository=os.environ['GITHUB_REPOSITORY']
    revision=os.environ['GITHUB_SHA']
    tag=os.environ['GITHUB_REF_NAME']
    version=admit(tag,revision)
    name=f'candidate-{tag}-{revision}'
    run_id=original_artifact(repository,name,revision)
    if run_id is None:
        token=os.environ['GH_TOKEN']; actor=os.environ['GITHUB_ACTOR']
        for path,ref in [('bloc',tag),('charts/bloc',version)]:
            if Registry('ghcr.io/rodalladea/'+path,token,actor).manifest(ref) is not None:
                raise SystemExit('Original candidate evidence unavailable for existing version; use a new version')
        if GitHubCompletion(repository).get(tag) is not None:
            raise SystemExit('Original candidate evidence unavailable for completed release; use a new version')
    with open(os.environ['GITHUB_OUTPUT'],'a') as output:
        print('candidate='+name,file=output)
        print('run_id='+str(run_id or ''),file=output)
        print('reuse='+str(run_id is not None).lower(),file=output)
