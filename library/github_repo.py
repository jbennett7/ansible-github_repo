#!/usr/bin/python

from os import environ
from requests.exceptions import HTTPError
import yaml
import json
import requests
import re

class AuthenticationError(Exception):
    pass

class ImmutableLabels(Exception):
    pass

class GithubRepository(object):
    def __init__(self, token, org, repo):
        self._connection = GithubConnection(token, org, repo).get_connection()
        self._header = { 'Authorization': 'token {}'.format(token) }
        self._url = "https://api.github.com/repos/{}/{}".format(org,repo)
        self._create_repo_url = "https://api.github.com/orgs/{}/repos".format(org)
        self._repo = repo
        self._org = org
        self.create_repository()

    def create_repository(self):
        r = requests.get(self._url,headers=self._header)
        if r.status_code != 200:
            r = requests.post(self._create_repo_url,json.dumps(dict(name=self._repo)))
            self.exists = True
            self.changed = True
        self._config = r.json()
        return r.status_code

    def get_config(self):
        return self._config
  
    def set_config_var(self, key, value):
        assert self._config.has_key(key), "{} is not a configurable value".format(key)
        self._config[key] = value
  
    def configs_equal(self, config):
        for key in config.keys():
            if self._config[key] != config[key]:
                return False
        return True

    def sync_config(self):
        # Update does not work with allow_squash_merge, allow_rebase_merge, or allow_merge_commits.
        url = "https://api.github.com/repos/{}/{}".format(self._org,self._repo)
        r = requests.post(url,json.dumps(self.get_config()),headers=self._header)
        return "{}:  {}".format(r.text,url)
  
    def get_labels(self):
        label_url = re.sub('{/name}','',self._config['labels_url'])
        label_list = requests.get(label_url,headers=self._header).json()

    def labels_equal(self, label_list):
        cur_label_list = self.get_labels()
        if len(cur_label_list) != len(label_list):
            return False
  
    def set_labels(self, label_list):
        assert isinstance(label_list, list), "label_list must be a list"
        for item in label_list:
            assert isinstance(item, dict), "label_list must be a list of dictionaries."
            assert sorted(item.keys()) == sorted([ 'color', 'name' ]), "invalid keys present."
            pattern = re.compile("[a-f0-9]{6}")
            assert pattern.match(item['color']), "<{}> color schema is wrong.".format(item['name'])
        self._labels = label_list
  
    def sync_labels(self):
        deleted_labels=[]
        added_labels=[]
        changed_labels=[]
        for label in self._connection.issues.labels.list().all():
            if not any(d["name"] == label.name for d in self._labels):
                # Some repositories have it so that their labels cannot be changed.
                try:
                    self._connection.issues.labels.delete(label.name)
                    deleted_labels.append(label.name)
                except NotFound:
                    raise ImmutableLabels, "This repository has immutable labels"
        for label in self._labels:
            if not any(o.name == label["name"] for o in self._connection.issues.labels.list().all()):
                self._connection.issues.labels.create(label)
                added_labels.append(label['name'])
        for new_label in self._labels:
            for old_label in self._connection.issues.labels.list().all():
                if old_label.name != new_label["name"]: continue
                if old_label.color != new_label["color"]:
                    self._connection.issues.labels.update(new_label["name"], new_label)
                    changed_labels.append(new_label["name"])
        return deleted_labels, added_labels, changed_labels
  
    def delete_repo(self):
        try:
            self._connection.repos.delete()
            return True
        except NotFound:
            return False

def github_repository_present(params):
    has_changed = False
    is_error = False
    token = params['token']
    orgname = params['orgname']
    label_list = params['label_list']
    del params['state']
    del params['token']
    del params['orgname']
    del params['label_list']
    config_changes = []
    label_changes = []
    gh = GithubRepository(token, orgname, params['name'])
    cur_config = gh.get_config()
    for key in params:
        if params[key] != cur_config[key]:
            config_changes.append("{}: {} => {}".format(key, cur_config[key], params[key]))
            has_changed = True
    if has_changed == True:
        gh.set_config(GithubRepositoryConfiguration(
            name = params['name'],
            description = params['description'],
            has_issues = params['has_issues'],
            has_projects = params['has_projects'],
            has_wiki = params['has_wiki'],
            homepage = params['homepage'],
            allow_squash_merge = params['allow_squash_merge'],
            allow_merge_commit = params['allow_merge_commit'],
            allow_rebase_merge = params['allow_rebase_merge'],
            private = params['private']
        ))
        if gh.exists == False:
            gh.create_repository()
            has_changed = True
        result = gh.sync_config()
    old_labels = gh.get_labels() 
    if not sorted(old_labels) == sorted(label_list):
        gh.set_labels(label_list)
        try:
            deleted_labels, added_labels, changed_labels = gh.sync_labels()
            has_changed = True
            label_changes = { "deleted_labels": deleted_labels, "added_labels": added_labels, "changed_labels": changed_labels }
        except ImmutableLabels as e:
            label_changes = { "state": str(e) }
            has_changed = False
    try: 
        result
    except:
        result = { "config_changes": config_changes, "label_changes": label_changes }
    return is_error, has_changed, result

def github_repository_absent(params):
    has_changed = False
    is_error = False
    token = params['token']
    orgname = params['orgname']
    label_list = params['label_list']
    del params['state']
    del params['token']
    del params['orgname']
    del params['label_list']
    gh = GithubRepository(token, orgname, params['name'])
    if gh.exists:
        has_changed = True
        gh.delete_repo()
    return is_error, has_changed, { "msg": "{} deleted.".format(params['name']) }

from ansible.module_utils.basic import *
if __name__ == '__main__':
    try:
        env_token = environ["GITHUB_TOKEN"]
    except:
        env_token = ""

    argument_spec = dict(
            token = dict(type = 'str', required = False, default = env_token),
            orgname = dict(type = 'str', required = True),
            name = dict(type = 'str', required = True),
            description = dict(type = 'str', required = False),
            private = dict(type = 'bool', required = False, default = True),
            has_issues = dict(type = 'bool', required = False, default = True),
            has_projects = dict(type = 'bool', required = False, default = True),
            has_wiki = dict(type = 'bool', required = False, default = False),
            homepage = dict(type = 'str', required = False, default = ""),
            label_list = dict(type = 'list', required = False, default = []),
            allow_squash_merge = dict(type = 'bool', required = False, default = True),
            allow_merge_commit = dict(type = 'bool', required = False, default = True),
            allow_rebase_merge = dict(type = 'bool', required = False, default = True),
            state = dict(type = 'str', required = False, default = 'present', choices = ['present', 'absent'])
    )

    choice_map = {
            'present': github_repository_present,
            'absent': github_repository_absent
    }

    module = AnsibleModule(argument_spec=argument_spec)
    is_error, has_changed, result = choice_map.get(module.params['state'])(module.params)

    if not is_error:
        module.exit_json(changed = has_changed, meta = result)
    else:
        module.fail_json(msg = result)
