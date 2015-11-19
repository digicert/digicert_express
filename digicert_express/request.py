import config
import requests

class Request(object):
	_api_key = None
	# We are only going to work with JSON here, deal with it B)
	_headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

	def __init__(self, api_key=None, **kwargs):
		if api_key:
			self._api_key = api_key
			self._headers['X-DC-DEVKEY'] = self._api_key

	# /order/certificate/<order_id>
	def get(self, endpoint, **kwargs):
		pass

	def put(self, endpoint, **kwargs):
		pass

	# /user/tempkey {'username': username, 'current_password': password}
	def post(self, endpoint, params):
		url = "{0}{1}".format(config.SERVICES_URL, endpoint)
		r = requests.post(url, json=params, headers=self._headers)
		return Response(r)

	def delete(self, endpoint, **kwargs):
		pass

class Response(object):
	status_code = None
	has_error = False
	data = None
	response = None
	reason = None
	internal_message = None

	def __init__(self, response):
		self.status_code = response.status_code
		self.reason = response.reason
		self.data = response.json()
		self.response = response
		self.check_valid()
		if self.has_error and 'errors' in self.data:
			self.internal_message = self.data['errors'][0]['message']

	def check_valid(self):
		if self.status_code not in [200, 204]:
			self.has_error = True

	def get_message(self):
		if self.internal_message:
			return self.internal_message
		return "Bad request! Status: {0}, Reason: {1}".format(self.status_code, self.reason)
