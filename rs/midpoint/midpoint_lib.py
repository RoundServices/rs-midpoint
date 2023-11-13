# rs-midpoint is available under the MIT License. https://github.com/RoundServices/rs-midpoint/
# Copyright (c) 2023, Round Services LLC - https://roundservices.biz/
#
# Author: Gustavo J Gallardo - ggallard@roundservices.biz
#

import base64
import json
import requests
import shutil
import time
import os
from xml.etree import ElementTree
from rs.utils import validators
from rs.utils import http
from rs.utils.basics import Logger

endpoints = {
    "ArchetypeType": "archetypes",
    "ConnectorHostType": "connectorHosts",
    "ConnectorType": "connectors",
    "FunctionLibraryType": "functionLibraries",
    "GenericObjectType": "genericObjects",
    "ObjectTemplateType": "objectTemplates",
    "OrgType": "orgs",
    "ResourceType": "resources",
    "RoleType": "roles",
    "SecurityPolicyType": "securityPolicies",
    "ShadowType": "shadows",
    "SystemConfigurationType": "systemConfigurations",
    "TaskType": "tasks",
    "UserType": "users",
    "ValuePolicyType": "valuePolicies"
}


class Midpoint:
    def __init__(self, mp_baseurl, mp_username, mp_password, properties, logger=Logger("Midpoint"), temp_file_path="/tmp/midpoint_object", iterations=10, interval=10):
        self._baseurl = mp_baseurl
        mp_credentials = "{}:{}".format(mp_username, mp_password)
        self._credentials = base64.b64encode(mp_credentials.encode())
        self._logger = logger
        self._properties = properties
        self._temp_file_path = temp_file_path
        url = "{}users/00000000-0000-0000-0000-000000000002".format(self._baseurl)
        headers = {'Authorization': 'Basic {}'.format(self._credentials.decode()), 'Content-Type': 'application/xml'}
        http.wait_for_endpoint(url, iterations, interval, logger, headers)


    def _midpoint_call(self, method, endpoint, oid, payload):
        url = self._baseurl + endpoint
        if method=="GET" or method=="PATCH" or method=="PUT":
            url = url + "/" + oid
        headers = {
            'Authorization': 'Basic {}'.format(self._credentials.decode()),
            'Content-Type': 'application/xml'
        }
        self._logger.debug("Calling URL: {} with method: {}, headers: {}", url, method, headers)
        self._logger.trace("payload: {}", payload)
        http_response = requests.request(method, url, headers=headers, data=payload)
        self._logger.trace("http_response: {}", http_response)
        response_code = http_response.status_code
        self._logger.trace("response_code: {}", response_code)
        if response_code not in [200, 201, 202, 204]:
            validators.raise_and_log(self._logger, IOError, "Invalid HTTP response received: '{}'.", response_code)
        response = http_response.text.encode('utf8')
        self._logger.trace("response: {}", response)
        return response


    def _get_endpoint(self, object_type):
        for endpoint_class, endpoint_rest in endpoints.items():
            if endpoint_class.lower().startswith(object_type.lower()):
                return endpoint_rest
        raise AttributeError("Can't find REST type for class " + object_type)


    def _get_oid_from_document(self, xml_data):
        tree_root = ElementTree.fromstring(xml_data)
        return tree_root.attrib['oid']


    def _get_objectType_from_document(self, xml_data):
        tree_root = ElementTree.fromstring(xml_data)
        # remove namespace
        object_type = tree_root.tag.split('}', 1)[1] if '}' in tree_root.tag else tree_root.tag
        return object_type


    def _get_endpoint_from_document(self, xml_data):
        object_type = self._get_objectType_from_document(xml_data)
        return self._get_endpoint(object_type)


    def get_object(self, object_type, object_oid):
        endpoint = self._get_endpoint(object_type)
        response = self._midpoint_call("GET", endpoint, oid=object_oid, payload=None)
        return response


    def get_object_by_name(self, object_type, object_name):
        endpoint = self._get_endpoint(object_type) + "/search"
        payload = """<?xml version="1.0" encoding="utf-8"?>
                    <query>
                        <filter>
                            <equal>
                                <path>name</path>
                                <value>{}</value>
                            </equal>
                        </filter>
                    </query>""".format(object_name)
        response = self._midpoint_call("POST", endpoint, payload=payload, oid=None)
        self._logger.trace("response: {}", response)
        tree_root = ElementTree.fromstring(response)
        objects = tree_root.findall('{http://midpoint.evolveum.com/xml/ns/public/common/api-types-3}object')
        self._logger.trace("objects: {}", objects)
        object = objects[0]
        self._logger.trace("object: {}", object)
        object_string = ElementTree.tostring(object, encoding="unicode")
        self._logger.trace("object_string: {}", object_string)
        return object_string


    def get_object_oid(self, object_type, object_name):
        object_document = self.get_object(object_type, object_name)
        return self._get_oid_from_document(object_document)


    def put_object(self, xml_data):
        endpoint = self._get_endpoint_from_document(xml_data)
        oid = self._get_oid_from_document(xml_data)
        response = self._midpoint_call("PUT", endpoint, oid=oid, payload=xml_data)
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
        response = self._midpoint_call("PATCH", endpoint, oid=oid, payload=xml_data)
        return response


    def patch_object_from_file(self, xml_file, endpoint, oid):
        self._logger.debug("Starting")
        xml_data = ""
        with open(xml_file, "r") as file_object:
            xml_data = file_object.read()
            file_object.close()
        response = self.patch_object(xml_data, endpoint, oid)
        return response


    def check_object_exists(self, object_type, object_oid):
        object_document = self.get_object(object_type, object_oid)
        if object_document is None:
            return False
        else:
            return True


    def _add_inducement(self, inducement_type, target_type, inducement_oid=None, inducement_name=None, target_oid=None, target_name=None):
        self._logger.trace("_add_inducement(inducement_type={}, inducement_oid={}, inducement_name={}, target_type={}, target_oid={}, target_name={}", inducement_type, inducement_oid, inducement_name, target_type, target_oid, target_name)
        target_object = {}
        if target_oid is not None:
            target_object = self.get_object(target_type, target_oid)
            if target_object is None:
                raise Exception("target_type: {}, target_oid: {} does not exist.".format(target_type, target_oid))
        elif target_name is not None:
            target_object = self.get_object_by_name(target_type, target_name)
            if target_object is None:
                raise Exception("target_type: {}, target_name: {} does not exist.".format(target_type, target_name))
            target_oid = self._get_oid_from_document(target_object)
        else:
            raise Exception("Either target_oid or target_name must be specified.")

        inducement_object = {}
        if inducement_oid is not None:
            inducement_object = self.get_object(inducement_type, inducement_oid)
            if inducement_object is None:
                raise Exception("inducement_type: {}, inducement_oid: {} does not exist.".format(inducement_type, inducement_oid))
        elif inducement_name is not None:
            inducement_object = self.get_object_by_name(inducement_type, inducement_name)
            if inducement_object is None:
                raise Exception("inducement_type: {}, inducement_name: {} does not exist.".format(inducement_type, inducement_name))
            inducement_oid = self._get_oid_from_document(inducement_object)
        else:
            raise Exception("Either inducement_oid or inducement_name must be specified.")

        # TODO: check if object already has the inducement
        self._logger.debug("Adding inducement type: {}, oid: {} to object type: {}, oid: {}", inducement_type, inducement_oid, target_type, target_oid)
        if inducement_type=="ResourceType":
            new_inducement = """<c:construction>
                                    <c:resourceRef type="c:ResourceType" oid="{}" />
                                </c:construction>""".format(inducement_oid)
        elif inducement_type=="RoleType":
            new_inducement = """<c:targetRef type="c:RoleType" oid="{}" />""".format(inducement_oid)
        else:
            raise Exception("Unknown structure for inducement")

        xml_data = """<objectModification
                    xmlns='http://midpoint.evolveum.com/xml/ns/public/common/api-types-3'
                    xmlns:c='http://midpoint.evolveum.com/xml/ns/public/common/common-3'
                    xmlns:t='http://prism.evolveum.com/xml/ns/public/types-3'>
                        <itemDelta>
                            <t:modificationType>add</t:modificationType>
                            <t:path>c:inducement</t:path>
                            <t:value>
                                {}
                            </t:value>
                        </itemDelta>
                    </objectModification>""".format(new_inducement)
        endpoint = self._get_endpoint(target_type)
        response = self.patch_object(xml_data, endpoint, target_oid)
        return response

    def add_resource_inducement_to_role(self, resource_oid=None, resource_name=None, role_oid=None, role_name=None):
        response = self._add_inducement(inducement_type="ResourceType", inducement_oid=resource_oid, inducement_name=resource_name, target_type="RoleType", target_oid=role_oid, target_name=role_name)
        return response

    def add_role_inducement_to_role(self, child_oid=None, child_name=None, parent_oid=None, parent_name=None):
        response = self._add_inducement(inducement_type="RoleType", inducement_oid=child_oid, inducement_name=child_name, target_type="RoleType", target_oid=parent_oid, target_name=parent_name)
        return response
    
    def wait_for_object(self, iterations, interval, object_type, object_oid=None, object_name=None):
        object_exists = False
        for iteration in range(iterations):
            self._logger.debug("Iteration #: {}", iteration)
            try:
                if object_oid is not None:
                    self._logger.debug("Checking if object exists. Type: {}, oid: {}", object_type, object_oid)
                    if self.check_object_exists(object_type, object_oid):
                        object_exists = True
                        break
                elif object_name is not None:
                    self._logger.debug("Checking if object exists. Type: {}, name: {}", object_type, object_name)
                    if self.get_object_by_name(object_type, object_name) is not None:
                        object_exists = True
                        self._logger.debug("Checking if object exists. Type: {}, name: {}", object_type, object_name)
                        break
                else:
                    self._logger.error("Either object_oid or object_name must be specified.")
            except:
                self._logger.debug("Exception while trying to find object_type: {}, object_oid: {}, object_name: {}", object_type, object_oid, object_name)
            self._logger.info("Waiting {} seconds for object_type: {}, object_oid: {}, object_name: {}", interval, object_type, object_oid, object_name)
            time.sleep(interval)
        if not object_exists:
            raise Exception("Gave up trying to find object_type: {}, object_oid: {}, object_name: {}".format(object_type, object_oid, object_name))
    
    def process_subfolders(self, subfolder_path):
        if not os.path.exists(subfolder_path):
            self._logger.error("Folder not found: {}.", subfolder_path)
            return
        self._logger.debug("Processing dir: {}.", subfolder_path)
        for object_type_folder in sorted(os.scandir(subfolder_path), key=lambda path: path.name):
            if object_type_folder.is_dir():
                self.process_folder(object_type_folder.path)

    def process_folder(self, folder_path):
        self._logger.debug("Processing dir: {}.", folder_path)
        if not os.path.exists(folder_path):
            self._logger.error("Folder not found: {}.", folder_path)
            return
        for file in sorted(os.scandir(folder_path), key=lambda path: path.name):
            if file.is_file():
                self.process_file(file)

    def process_file(self, file):
        if not os.path.exists(file):
            self._logger.error("File not found: {}.", file)
            return
        
        if file.path.endswith(".xml"):
            self._logger.debug("Processing file: {}.", file.name)
            shutil.copyfile(file.path, self._temp_file_path)
            self._properties.replace(self._temp_file_path)
            self.put_object_from_file(self._temp_file_path)

            with open(file, "r") as file_object:
                xml_data = file_object.read()
                file_object.close()
            oid = self._get_oid_from_document(xml_data)
            object_type = self._get_objectType_from_document(xml_data)
            self.wait_for_object(5, 10, object_type, object_oid=oid)

        if file.is_file() and file.path.endswith(".patch"):
            self._logger.debug("Processing file: {}.", file.name)
            shutil.copyfile(file.path, self._temp_file_path)
            self._properties.replace(self._temp_file_path)
            self._logger.trace("File name: {}.", file.name)
            oid = file.name.split(".")[0]
            folder_path = os.path.dirname(file)
            self._logger.debug("Spliting folder name for endpoint: {}.", folder_path)
            endpoint = folder_path.split("_")[1]
            self.patch_object_from_file(self._temp_file_path, endpoint, oid)

        if file.is_file() and file.path.endswith(".json"):
            self._logger.debug("Processing file: {}.".format(file.path))
            with open(file) as f:
                data = json.load(f)
            self._logger.debug("Reading json: {}".format(data))
            self._logger.debug("Child name: {}, Parent name: {}.", data['child_name'], data['parent_name'])
            match data["operation_type"]:
                case "add_role_inducement_to_role":
                    self.wait_for_object(2, 30, "RoleType", object_name=data['parent_name'])
                    self.wait_for_object(2, 30, "RoleType", object_name=data['child_name'])
                    self.add_role_inducement_to_role(child_name=data['child_name'], parent_name=data['parent_name'])
                case _:
                    self._logger.error("OperationType is unknown: {}.", data["operation_type"])