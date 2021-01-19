import json
import logging
import re

import requests

logging.basicConfig(level=logging.INFO, format='%(filename)-12s:%(lineno)-4s:%(name)s: %(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)


class NexusOSS:
    def __init__(self, user, password, nexus_root="https://nexus-oss.lge.com/"):
        # nexus_root="https://"
        self.user = user
        self.password = password
        self.nexus_root = nexus_root
        self.API_base_url = "service/rest/"
        self.API_url = nexus_root + self.API_base_url
        self.no_auth_role = "nx-no-authorized"
        check_url = self.API_url + "v1/status/check"
        check_health = requests.get(check_url, auth=(user, password))
        if check_health.status_code != 200:
            logger.error(f"Check the connection to your nexus site: {nexus_root}")
        else:
            logger.error(f"Health Check: OK = {nexus_root}")

    def create_content_selector(self, name, expression, description=""):
        api_version = "beta"
        create_data = {"name": name, "expression": expression, "description": description}
        create_cs = requests.post(self.API_url + f"{api_version}/security/content-selectors",
                                  auth=(self.user, self.password), json=create_data)
        logger.error(create_cs.status_code)
        return create_cs.status_code

    def delete_content_selector(self, name):
        api_version = "beta"
        delete_cs = requests.delete(self.API_url + f"{api_version}/security/content-selectors/{name}",
                                    auth=(self.user, self.password))
        logger.error(delete_cs.status_code)
        if not re.compile("^2.*").match(str(delete_cs.status_code)):
            logger.error(f"Content selector '{name}' can't be delete with the status code {delete_cs.status_code}")
            logger.error(f"Error message:\n{delete_cs.text}")
        else:
            logger.warning(f"Content selector '{name}': Deleted")
        return delete_cs.status_code

    def create_privilege_for_repository_content_selector(self, name, description, content_selector_name,
                                                         actions=["READ"], format="*",
                                                         repository="*"):
        req_body = {
            "name": name,
            "description": description,
            "actions": actions,
            "format": "*",
            "repository": repository,
            "contentSelector": content_selector_name
        }
        api_version = "beta"
        create_privilege = requests.post(
            self.API_url + f"{api_version}/security/privileges/repository-content-selector",
            auth=(self.user, self.password), json=req_body)
        if re.compile("^2.*").match(f"{create_privilege.status_code}"):
            logger.info(f"Privilege '{name}' is created")
        else:
            logger.error(f"Privilege '{name}' is not created")
            logger.error(f"Error message:\n{create_privilege.text}")
        return create_privilege.status_code

    def delete_privilege(self, name):
        api_version = "beta"
        delete_privilege = requests.delete(
            self.API_url + f"{api_version}/security/privileges/{name}",
            auth=(self.user, self.password))
        if not re.compile("^2.*").match(str(delete_privilege.status_code)):
            logger.error(f"Privilege '{name}' can't be delete with the status code {delete_privilege.status_code}")
            logger.error(f"Error message:\n{delete_privilege.text}")
        else:
            logger.warning(f"Privilege '{name}': Deleted")

        return delete_privilege.status_code

    def create_nexus_role(self, role_name, description="", privileges=[""], roles=[""]):
        api_version = "beta"
        if description == "":
            role_description = f"A nexus role for {role_name}"
        else:
            role_description = description
        req_body = {
            "id": role_name,
            "name": role_name,
            "description": role_description,
            "privileges": privileges
        }
        create_role = requests.post(self.API_url + f"{api_version}/security/roles",
                                    auth=(self.user, self.password), json=req_body)
        if re.compile("^2.*").match(f"{create_role.status_code}"):
            logger.info(f"Role '{role_name}' is created")
        else:
            logger.error(f"Role '{role_name}' is not created")
            logger.error(f"Error message:\n{create_role.text}")
        return create_role.status_code

    def delete_nexus_role(self, role_name):
        api_version = "beta"
        delete_role = requests.delete(self.API_url + f"{api_version}/security/roles/{role_name}",
                                      auth=(self.user, self.password))
        if re.compile("^2.*").match(f"{delete_role.status_code}"):
            logger.info(f"Role '{role_name}' is removed")
        else:
            logger.error(f"Role '{role_name}' is not removed")
            logger.error(f"Error message:\n{delete_role.text}")
        return delete_role.status_code

    def delete_user(self, user_id):
        api_version = "beta"
        delete_user = requests.delete(
            self.API_url + f"{api_version}/security/users/{user_id}",
            auth=(self.user, self.password))
        users = json.loads(delete_user.text)
        return delete_user.status_code

    def get_role(self, role_name):
        api_version = "beta"
        get_role_res = requests.get(
            self.API_url + f"{api_version}/security/roles/{role_name}?source=default", auth=(self.user, self.password))
        return get_role_res

    @staticmethod
    def get_role_name_for_project(project_name):
        prj_name_output = project_name.replace("-", "_").replace("/", "-")
        return prj_name_output

    def disable_user(self, user_id):
        api_version = "beta"
        user_info = self.get_user(user_id)
        user_info['roles'] = [self.no_auth_role]
        disable_user = requests.put(
            self.API_url + f"{api_version}/security/users/{user_id}",
            auth=(self.user, self.password), json=user_info)
        return disable_user.status_code, disable_user.text

    def get_user(self, user_id):
        api_version = "beta"
        get_users = requests.get(
            self.API_url + f"{api_version}/security/users/?userId={user_id}",
            auth=(self.user, self.password))
        users = json.loads(get_users.text)
        user_info = list(filter(lambda user: user['userId'] == user_id, users))
        return user_info[0]

    def get_users(self):
        api_version = "beta"
        get_users = requests.get(
            self.API_url + f"{api_version}/security/users",
            auth=(self.user, self.password))
        users = json.loads(get_users.text)
        return users

    def update_user(self, user_id, user_data):
        api_version = "beta"
        logger.info("Update a user information from server: " + user_id)
        logger.debug(user_data)
        update_user = requests.put(
            self.API_url + f"{api_version}/security/users/{user_id}",
            auth=(self.user, self.password), json=user_data)
        logger.info(update_user.status_code)
        logger.info(update_user.text)
        return update_user.status_code

    def add_roles_to_user(self, user_id, role_name):
        api_version = "beta"
        logger.info("Get a user information from server: " + user_id)
        user_json = self.get_user(user_id)
        user_json['roles'].append(role_name)
        user_json['lastName'] = user_id
        logger.info(user_json)
        update_user = requests.put(
            self.API_url + f"{api_version}/security/users/{user_id}",
            auth=(self.user, self.password), json=user_json)
        logger.error(update_user.status_code)
        logger.error(update_user.text)
        return update_user.status_code

    def remove_role_from_user(self, user_id, role_name, default_role="nx-anonymous"):
        api_version = "beta"
        logger.info("Get a user information from server: " + user_id)
        user_json = self.get_user(user_id)
        # user_json = json.loads(self.get_user(user_id))[0]
        user_json['roles'].remove(role_name)
        if len(user_json['roles']) == 0:
            user_json['roles'].append(default_role)
        logger.info(user_json)
        update_user = requests.put(
            self.API_url + f"{api_version}/security/users/{user_id}",
            auth=(self.user, self.password), json=user_json)
        logger.info(update_user.status_code)
        logger.info(update_user.text)
        return update_user.status_code

    def create_docker_user_permission(self, userId):
        user_permission_name = f"nx-docker-person-{userId}"
        user_cs_expression = f"format == \"docker\" and path =^ \"/v2/person/{userId}/\""
        # Create a content selector
        self.create_content_selector(user_permission_name, user_cs_expression,
                                     f"Docker content selector for a user {userId}")
        # Create a privilege
        self.create_privilege_for_repository_content_selector(user_permission_name,
                                                              f"Privilege for {user_permission_name}",
                                                              user_permission_name, ["ALL"], "docker", )
        # Create a role
        self.create_nexus_role(user_permission_name, privileges=[user_permission_name])

        # Add roles to a user
        self.add_roles_to_user(userId, user_permission_name)

    def create_docker_project_permission(self, prj_name_input):
        permission_idx = "project"
        prj_name = self.get_role_name_for_project(project_name=prj_name_input)
        permission_name = f"nx-docker-{permission_idx}-{prj_name}"
        cs_expression = f"format == \"docker\" and path =^ \"/v2/{permission_idx}/{prj_name_input}/\""
        # Create a content selector
        self.create_content_selector(permission_name, cs_expression,
                                     f"Docker content selector for a {permission_idx} {prj_name}")
        # Create a privilege
        self.create_privilege_for_repository_content_selector(permission_name,
                                                              f"Privilege for {permission_name}",
                                                              permission_name, ["ALL"], "docker", )
        # Create a role
        self.create_nexus_role(permission_name, privileges=[permission_name])

    def delete_docker_user_permission(self, user_id):
        logger.info("User Id: " + user_id)
        user_permission_name = f"nx-docker-person-{user_id}"
        logger.info(f"Remove a role named as {user_permission_name}  from {user_id}")
        user_json = self.get_user(user_id)
        nexus_roles = user_json['roles']
        user_json['roles'] = []
        for each_role in nexus_roles:
            if each_role != user_permission_name:
                user_json['roles'].append(each_role)
        self.update_user(user_id, user_json)
        self.delete_nexus_role(user_permission_name)
        self.delete_privilege(user_permission_name)
        self.delete_content_selector(user_permission_name)

    def delete_docker_project_permission(self, prj_name):
        logger.info(f"Project name: {prj_name}")
        permission_name = f"nx-docker-project-{self.get_role_name_for_project(prj_name)}"
        self.delete_nexus_role(permission_name)
        self.delete_privilege(permission_name)
        self.delete_content_selector(permission_name)
