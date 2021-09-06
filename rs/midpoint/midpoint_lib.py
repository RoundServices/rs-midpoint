# rs-midpoint is available under the MIT License. https://gitlab.com/roundservices/rs-midpoint/
# Copyright (c) 2021, Round Services LLC - https://roundservices.biz/
#
# Author: Gustavo J Gallardo - ggallard@roundservices.biz
#

import base64
import requests
from xml.etree import ElementTree
from rs.utils import validators
from rs.utils import http
from rs.utils.basics import Logger

endpoints = {
    "ConnectorType": "connectors",
    "ConnectorHostType": "connectorHosts",
    "GenericObjectType": "genericObjects",
    "ResourceType": "resources",
    "UserType": "users",
    "ObjectTemplateType": "objectTemplates",
    "SystemConfigurationType": "systemConfigurations",
    "TaskType": "tasks",
    "ShadowType": "shadows",
    "RoleType": "roles",
    "ValuePolicyType": "valuePolicies",
    "SecurityPolicyType": "securityPolicies",
    "OrgType": "orgs",
    "FunctionLibraryType": "functionLibraries"
}


class Midpoint:
    def __init__(self, mp_baseurl, mp_username, mp_password, logger=Logger("Midpoint"), iterations=10, interval=10):
        self._baseurl = mp_baseurl
        mp_credentials = "{}:{}".format(mp_username, mp_password)
        self._credentials = base64.b64encode(mp_credentials.encode())
        self._logger = logger
        url = "{}users/00000000-0000-0000-0000-000000000002".format(self._baseurl)
        headers = {'Authorization': 'Basic {}'.format(self._credentials.decode()), 'Content-Type': 'application/xml'}
        http.wait_for_endpoint(url, iterations, interval, logger, headers)

    def _midpoint_call(self, method, endpoint, payload, oid=None):
        url = self._baseurl + endpoint
        if method == "PATCH" or method == "GET":
            url = url + "/" + oid
        headers = {
            'Authorization': 'Basic {}'.format(self._credentials.decode()),
            'Content-Type': 'application/xml'
        }
        self._logger.debug("Calling URL: {} with method: {}, headers: {}".format(url, method, headers))
        self._logger.trace("payload: {}".format(payload))
        http_response = requests.request(method, url, headers=headers, data=payload)
        self._logger.trace("http_response: {}, type: {}".format(http_response, type(http_response)))
        response_code = http_response.status_code
        self._logger.trace("response_code: {}, type: {}".format(response_code, type(response_code)))
        if response_code not in [200, 201, 202, 204]:
            validators.raise_and_log(self._logger, IOError, "Invalid HTTP response received: '{}'.", response_code)
        response = http_response.text.encode('utf8')
        self._logger.trace("response: {}, type: {}".format(response, type(response)))
        return response

    def _get_endpoint(self, xml_data):
        self._logger.trace("xml_data: {}, type: {}".format(xml_data, type(xml_data)))
        tree_root = ElementTree.fromstring(xml_data)
        object_oid = tree_root.attrib['oid']
        # remove namespace
        object_class = tree_root.tag.split('}', 1)[1] if '}' in tree_root.tag else tree_root.tag
        self._logger.debug("object_class: {}, type: {}".format(object_class, type(object_class)))
        for endpoint_class, endpoint_rest in endpoints.items():
            if endpoint_class.lower().startswith(object_class.lower()):
                return "{}/{}".format(endpoint_rest, object_oid)
        raise AttributeError("Can't find REST type for class " + object_class)

    def put_object(self, xml_data):
        endpoint = self._get_endpoint(xml_data)
        response = self._midpoint_call("PUT", endpoint, xml_data)
        return response

    def put_object_from_file(self, xml_file):
        self._logger.debug("Starting")
        xml_data = ""
        with open(xml_file, "r") as file_object:
            xml_data = file_object.read()
            file_object.close()
        response = self.put_object(xml_data)
        return response

    def patch_object(self, xml_data, endpoint, oid):
        self._logger.debug("Starting")
        response = self._midpoint_call("PATCH", endpoint, xml_data, oid)
        return response

    def patch_object_from_file(self, xml_file, endpoint, oid):
        self._logger.debug("Starting")
        xml_data = ""
        with open(xml_file, "r") as file_object:
            xml_data = file_object.read()
            file_object.close()
        response = self.patch_object(xml_data, endpoint, oid)
        return response
