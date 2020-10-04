import sys
import urllib
import argparse
from .state import State, EndpointState, RequestState, StateVersionError
import io
import logging
from .init import init_endpoint
from .request import post_request
from .jwt import create_access_token

try:
    state = State.load()
except IOError:
    state = State()
    state.save()
except StateVersionError:
    state = State()
    state.save()


# Prints the Authorization HTTP Header to stdout
def authorization(state: State):
    sys.stdout.write (f"Authorization: Bearer {state.endpoint.auth_token}")

def main():
    parser = argparse.ArgumentParser(prog='vaupie', description='Perform VAU-Client commands')
    parser.add_argument('action', choices=['init', 'req', 'auth', 'jwt'], help='action to execute')
    parser.add_argument('endpoint', nargs="?", type=str, help='VAU Endpoint, e.g. http://localhost:3000/')
    parser.add_argument('token', nargs="?", type=str, help='JWT Auth Token')
    parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")

    args = parser.parse_args()

    FORMAT = '[vaupie] %(message)s'
    if args.verbose == True:
        logging.basicConfig(format=FORMAT, level=logging.DEBUG)
        logging.error("Verbose logging is on")
    else:
        logging.basicConfig(format=FORMAT, level=logging.ERROR)

    if args.action == "init" and args.endpoint == None:
        parser.error("Endpoint URL reqired")

    if args.action == "init" and args.token == None:
        args.token = create_access_token(open('.pki/idp-private.pem').read())
        #parser.error("JWT Auth token reqired")

    if args.action == "init":
        state.endpoint = init_endpoint(args.endpoint, args.token)
        state.save()
        logging.debug(f"State saved")

    else:
        if state.endpoint == None:
            exit("error: endpoint is not configured. Issue 'vau.py init' command first.")

        if args.action == "req":
            (userpseudonym, version, request_id, response) = post_request(
                state.endpoint.userpseudonym,
                state.endpoint.base_url,  
                state.endpoint.x509, 
                state.endpoint.auth_token,
                sys.stdin.buffer)
            state.endpoint.userpseudonym = userpseudonym
            state.save()

            print (response.decode('utf-8'))
        elif args.action == "auth":
            authorization(state=state)
        elif args.action == 'jwt':
            access_token = create_access_token(open('.pki/idp-private.pem').read())
            print(access_token)
        else:
            parser.error(f"invalid action: {args.action}")        
    

