from vaupie.state import State, EndpointState, RequestState, StateVersionError
import secrets
import pytest

TEMP_STATE="/tmp/vaupy_test_state.json"

def test_config():
    state = State()
    state.endpoint = EndpointState(base_url="http://localhost:3000", auth_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    request_id = secrets.token_bytes(16).hex()
    response_key = secrets.token_bytes(16).hex()
    request = RequestState(request_id, response_key)
    state.endpoint.requests.append(request)

    assert state.endpoint.find_request(request_id) != None
    assert state.endpoint.find_request(request_id).response_key == response_key

    state.save(TEMP_STATE)

    state2 = State.load(TEMP_STATE)
    
    assert state2.endpoint.base_url == state.endpoint.base_url
    assert len(state2.endpoint.requests) == 1

    state2.version = 0
    state2.save(TEMP_STATE)

    with pytest.raises(StateVersionError):
        state3 = State.load(TEMP_STATE)
