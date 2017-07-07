#!/usr/bin/python

from pygithub3 import Github
from pygithub3.exceptions import UnprocessableEntity, NotFound
from os import environ
from requests.exceptions import HTTPError
import yaml
import json
import re

class AuthenticationError(Exception):
    pass

class ImmutableLabels(Exception):
    pass

class GithubRepositoryConfiguration(object):
    def __init__(self, name="", description=None, has_issues=True, has_projects=True, has_wiki=False, homepage="", private=True):
        assert isinstance(has_issues, bool), "<has_issues> has to be a boolean value."
        assert isinstance(has_projects, bool), "<has_projects> has to be a boolean value."
        assert isinstance(has_wiki, bool), "<has_wiki> has to be a boolean value."
        assert isinstance(private, bool), "<private> has to be a boolean value."
        self._config = {
                "name": name,
                "description": description,
                "has_issues": has_issues,
                "has_projects": has_projects,
                "has_wiki": has_wiki,
                "homepage": homepage,
                "private": private}

    def __getitem__(self,key):
        assert key in self._config.keys(), "<{}> is not a configuration value.".format(key)
        return self._config[key]

    def get_config(self):
        return self._config

class GithubConnection(object):
    def __init__(self, token, org, repo):
        assert token, "An authorization token needs to be provided"
        assert org, "An organization needs to be provided"
        assert repo, "The repository name needs to be provided"
        self._connection = Github(token=token, user=org, repo=repo)
        try:
            org_list = self._connection.orgs.list().all()
            assert any(o.login == org for o in org_list), "Incorrect organization specified"
        except HTTPError as e:
            raise AuthenticationError, "The authentication token does not work: {}".format(str(e))

    def get_connection(self):
        return self._connection

class GithubRepository(object):
    def __init__(self, token, org, repo):
        self._connection = GithubConnection(token, org, repo).get_connection()
        try:
            self._retrieve_repository(org, repo)
            self.exists = True
        except NotFound:
            self._config = GithubRepositoryConfiguration(name=repo)
            self.exists = False
  
    def create_repository(self):
        self._connection.repos.create(self._config.get_config())
        self.exists = True
  
    def _retrieve_repository(self, org, repo):
        r = self._connection.repos.get(org, repo)
        self._config = GithubRepositoryConfiguration(
                r.name,
                r.description,
                r.has_issues,
                r.has_projects,
                r.has_wiki,
                r.homepage,
                r.private)
        self._labels = []
        label_list = self._connection.issues.labels.list().all()
        for label in label_list:
            self._labels.append({"name": label.name, "color": label.color})
  
    def get_config(self):
        try:
            return self._config.get_config()
        except AttributeError:
            return {}
  
    def set_config(self, config):
        assert isinstance(config, GithubRepositoryConfiguration), "Specify a GithubRepositoryConfiguration Object"
        assert config["name"], "A name needs to be added"
        self._config = config
  
    def sync_config(self):
        self._connection.repos.update(self._config.get_config())
  
    def get_labels(self):
        try:
            return self._labels
        except AttributeError:
            return []
  
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
    if gh.exists == False:
        gh.create_repository()
        has_changed = True
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
            private = params['private']
        ))
        gh.sync_config()
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
    return False, False, { "msg": "Not Implemented" }

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
