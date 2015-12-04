import config
import requests
import loggers
from requests.exceptions import ConnectionError


class Request(object):
    _api_key = None
    # We are only going to work with JSON here, deal with it B)
    _headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

    def __init__(self, api_key=None, **kwargs):
        if api_key:
            self._api_key = api_key
            self._headers['X-DC-DEVKEY'] = self._api_key
        if not api_key and config.API_KEY:
            self._api_key = config.API_KEY
            self._headers['X-DC-DEVKEY'] = self._api_key
        self.log = loggers.get_logger(__name__)

    # /order/certificate/<order_id>
    def get(self, endpoint, params=None):
        try:
            # TODO add params to GET query string (aka url)
            url = "{0}{1}".format(config.SERVICES_URL, endpoint)
            r = requests.get(url, headers=self._headers)
            return Response(r)
        except ConnectionError as ex:
            self.log.error("Failed processing [GET] request on endpoint {0} with message {1}".format(endpoint, ex.message))
            return ErrorResponse(ex)

    def put(self, endpoint, params):
        try:
            url = "{0}{1}".format(config.SERVICES_URL, endpoint)
            r = requests.put(url, json=params, headers=self._headers)
            return Response(r)
        except ConnectionError as ex:
            self.log.error("Failed processing [PUT] request on endpoint {0} with message {1}".format(endpoint, ex.message))
            return ErrorResponse(ex)

    # /user/tempkey {'username': username, 'current_password': password}
    def post(self, endpoint, params):
        try:
            url = "{0}{1}".format(config.SERVICES_URL, endpoint)
            r = requests.post(url, json=params, headers=self._headers)
            return Response(r)
        except ConnectionError as ex:
            self.log.error("Failed processing [POST] request on endpoint {0} with message {1}".format(endpoint, ex.message))
            return ErrorResponse(ex)

    def delete(self, endpoint, **kwargs):
        pass


class Response(object):
    status_code = None
    has_error = False
    data = None
    response = None
    reason = None
    internal_message = None
    accept_status_codes = []

    def __init__(self, response):
        self.status_code = response.status_code
        self.reason = response.reason
        self.data = response.json()
        self.response = response
        self.check_valid()
        if self.has_error and 'errors' in self.data:
            self.internal_message = self.data['errors'][0]['message']

    def check_valid(self):
        if str(self.status_code)[0] != '2' and self.status_code not in self.accept_status_codes:
            self.has_error = True

    def get_message(self):
        if self.internal_message:
            return self.internal_message
        return "Bad request! Status: {0}, Reason: {1}".format(self.status_code, self.reason)

    def is_response_error(self):
        return False

class ErrorResponse(Response):
    exception = None

    def __init__(self, ex):
        self.has_error = True
        self.exception = ex
        self.internal_message = ex.message

    def is_response_error(self):
        return True
