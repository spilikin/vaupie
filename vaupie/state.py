from typing import List
from collections import namedtuple
import json
from time import time
from pathlib import Path

STATE_VERSION=2
STATE_FILENAME = f"{Path.home()}/.vaupy.json"

class StateVersionError(Exception):
    pass

class StateEncoder(json.JSONEncoder):
    def default(self, o):
        d = dict(o.__dict__)
        d['type'] = type(o).__name__
        return d    

def stateDecoder(stateDict):
    obj_type = stateDict.pop('type', None)
    if obj_type == 'State':
        if stateDict['version'] != STATE_VERSION:
            raise StateVersionError
        return State(**stateDict)
    elif obj_type == 'EndpointState':
        return EndpointState(**stateDict)
    elif obj_type == 'RequestState':
        return RequestState(**stateDict) 

    return namedtuple('X', stateDict.keys())(*stateDict.values())

class RequestState():
    def __init__(self, request_id: str, response_key: str, timestamp: int = int(time())):
        self.request_id = request_id
        self.response_key = response_key
        self.timestamp = timestamp

class EndpointState():
    def __init__(self, base_url: str, auth_token: str, x509: str = None, userpseudonym: str = '0', requests: List[RequestState] = []):
        self.base_url = base_url
        self.auth_token = auth_token
        self.x509 = x509
        self.userpseudonym = userpseudonym
        self.requests = requests

    def find_request(self, request_id: str):
        return next((x for x in self.requests if x.request_id == request_id), None)

class State():
    default_endpoint = None
    def __init__(self, version = STATE_VERSION, endpoint: EndpointState = None):
        self.version = version
        self.endpoint = endpoint

    def save(self, filename=STATE_FILENAME):
        with open(filename, "w") as f:
            json.dump(self, f, indent=2, cls=StateEncoder)
    
    @staticmethod
    def load(filename=STATE_FILENAME):
        with open(filename, "r") as f:
            state = json.load(f, object_hook=stateDecoder)
        return state





