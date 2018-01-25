import urllib
import json
import requests
import logging
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

logger = logging.getLogger()
logger.setLevel(logging.WARNING)
formatter = logging.Formatter('%(asctime)s%(levelname)10s:%(filename)15s:%(lineno)4d:%(funcName)10s: %(message)s')
ch = logging.StreamHandler()
# ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)


class NexusRepo:
    def __init__(self, url, user, password):
        self.url = url
        self.username = user
        self.password = password

if __name__ == "__main__":
    gerrit_url = input("Nexus Url: ")
    user_account = input("User account: ")
    user_password = input("User Password: ")
    g = NexusRepo(gerrit_url, user_account, user_password)
