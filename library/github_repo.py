#!/usr/bin/python

import json
from os import environ
import re
import requests
from requests.exceptions import HTTPError
import yaml

CONFIGURABLE_KEY_LIST = [
    'name',
    'description',
    'private',
    'has_issues',
    'has_projects',
    'has_wiki',
    'homepage',
    'allow_squash_merge',
    'allow_merge_commit',
    'allow_rebase_merge']

# HTML SUCCESS CODES
OK = 200
CREATED = 201
ACCEPTED = 202
NO_CONTENT = 204

# HTML ERROR CODES
BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
NOT_FOUND = 404


GITHUB_API = "https://api.github.com"


class AuthenticationError(Exception):
    pass


class ImmutableLabels(Exception):
    pass


class HTMLError(Exception):
    pass


class GithubRepository(object):
    def __init__(self, token, org, repo):
        self._header = {'Authorization': 'token {}'.format(token)}
        self._url = "{}/repos/{}/{}".format(GITHUB_API, org, repo)
        self._org_create_repo_url = "{}/orgs/{}/repos".format(GITHUB_API, org)
        self._user_create_repo_url = "{}/user/repos".format(GITHUB_API)
        self._repo = repo
        self._org = org

    def create_repository(self):
        r = requests.get(self._url, headers=self._header)
        if r.status_code != OK:
            r = requests.post(self._org_create_repo_url, data=json.dumps(
                dict(name=self._repo)), headers=self._header)
            if r.status_code != CREATED:
                r = requests.post(self._org_create_repo_url, data=json.dumps(dict(name=self._repo)), headers=self._header)
        self._config = dict((k, r.json()[k]) for k in CONFIGURABLE_KEY_LIST)
        self._labels_url = re.sub('{/name}', '', r.json()['labels_url'])
        return r.status_code, r.text

    def get_config(self):
        return self._config

    def set_config_var(self, key, value):
        assert key in self._config, "{} is not a configurable value".format(key)
        self._config[key] = value

    def configs_equal(self, config):
        for key in config.keys():
            if self._config[key] != config[key]:
                return False
        return True

    def sync_config(self):
        # Update does not work with allow_squash_merge, allow_rebase_merge, or allow_merge_commits.
        r = requests.post(
            self._url,
            json.dumps(self.get_config()),
            headers=self._header)
        return r, self._url, self.get_config()

    def get_labels(self):
        label_list = requests.get(
            self._labels_url,
            headers=self._header).json()
        return label_list

    def labels_equal(self, label_list):
        current_label_list = [{
            'name': d['name'],
            'color': d['color']} for d in self.get_labels()]
        return current_label_list == label_list

    def set_labels(self, label_list):
        deleted_labels = []
        added_labels = []
        changed_labels = []
        current_label_list = self.get_labels()
        for label in current_label_list:
            if not any(d["name"] == label['name'] for d in label_list):
                # Some repositories have it so that their labels cannot be changed.
                r = requests.delete(label['url'], headers=self._header)
                if r.status_code != NO_CONTENT:
                    raise ImmutableLabels(
                        "This repository has immutable labels")
                deleted_labels.append(label['name'])
        for label in label_list:
            if not any(d['name'] == label['name'] for d in current_label_list):
                r = requests.post(
                    self._labels_url,
                    headers=self._header,
                    data=json.dumps(label))
                added_labels.append(label['name'])
        for new_label in label_list:
            for old_label in current_label_list:
                if old_label['name'] == new_label['name']:
                    if old_label['color'] != new_label['color']:
                        changed_labels.append(new_label['name'])
                        r = requests.post(old_label['url'],headers=self._header, data=json.dumps(new_label))
        return deleted_labels, added_labels, changed_labels

    def delete_repository(self):
        return requests.delete(self._url, headers=self._header)


def github_repository_present(params):
    has_changed = False
    is_error = False
    message = {'msg': {}}
    token = params['token']
    orgname = params['orgname']
    label_list = params['label_list']
    del params['state']
    del params['token']
    del params['orgname']
    del params['label_list']
    config_changes = []
    gh = GithubRepository(token, orgname, params['name'])
    status, results = gh.create_repository()
    if status == CREATED:
        has_changed = True
        message['msg']['create_repo'] = True
    elif status == OK:
        message['msg']['create_repo'] = False
    else:
        is_error = True
        message['msg']['create_repo_error'] = {
            'status': status,
            'message': results}
    cur_config = gh.get_config()
    for key in params:
        if params[key] != cur_config[key]:
            config_changes.append("{}: {} => {}".format(
                key,
                cur_config[key],
                params[key]))
            has_changed = True
            gh.set_config_var(key, params[key])
            results, url, config = gh.sync_config()
    message['msg']['repo_config_changes'] = config_changes
    message['msg']['repo_config_changes_status'] = results.status_code
    message['msg']['repo_config_changes_url'] = url
    message['msg']['repo_config_changes_config'] = config
    current_label_list = list(dict((k, label[k]) for k in ['name', 'color']) for label in gh.get_labels())
    if label_list != current_label_list:
        deleted_labels, added_labels, changed_labels = gh.set_labels(
            label_list)
        has_changed = True
        message['msg']['labels_changes'] = {
            'deleted_labels': deleted_labels,
            'added_labels': added_labels,
            'changed_labels': changed_labels}
    else:
        message['msg']['labels_changes'] = False
    return is_error, has_changed, message


def github_repository_absent(params):
    has_changed = False
    is_error = False
    token = params['token']
    orgname = params['orgname']
    message = {'msg': {}}
    del params['state']
    del params['token']
    del params['orgname']
    del params['label_list']
    gh = GithubRepository(token, orgname, params['name'])
    r = gh.delete_repository()
    message['msg']['deleted_repo'] = params['name']
    message['msg']['deleted_repo_status'] = r.status_code
    if r.status_code == NO_CONTENT:
        has_changed = True
    return is_error, has_changed, message

from ansible.module_utils.basic import *
if __name__ == '__main__':
    try:
        env_token = environ["GITHUB_TOKEN"]
    except Exception:
        env_token = ""

    argument_spec = dict(
        token=dict(type='str', required=False, default=env_token),
        orgname=dict(type='str', required=True),
        name=dict(type='str', required=True),
        description=dict(type='str', required=False),
        private=dict(type='bool', required=False, default=True),
        has_issues=dict(type='bool', required=False, default=True),
        has_projects=dict(type='bool', required=False, default=True),
        has_wiki=dict(type='bool', required=False, default=False),
        homepage=dict(type='str', required=False, default=""),
        label_list=dict(type='list', required=False, default=[]),
        allow_squash_merge=dict(type='bool', required=False, default=True),
        allow_merge_commit=dict(type='bool', required=False, default=True),
        allow_rebase_merge=dict(type='bool', required=False, default=True),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent']))

    choice_map = {
        'present': github_repository_present,
        'absent': github_repository_absent}

    module = AnsibleModule(argument_spec=argument_spec)
    is_error, has_changed, result = choice_map.get(module.params['state'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg=result)
