import json

# Expect to run on the output of Kibana for the following query:
# {
#     "from": 0,
#     "size": 10000,
#     "_source": ["request", "infos.waf_data.filter"],
#     "query":
#     {
#         "function_score":
#         {
#             "query":
#             {
#                 "bool":
#                 {
#                     "must_not": [
#                     {
#                         "match_phrase":
#                         {
#                             "application":
#                             {
#                                 "query": "5b3d7b48f895b400191e101f"
#                             }
#                         }
#                     },
#                     {
#                         "match_phrase":
#                         {
#                             "application":
#                             {
#                                 "query": "5d53d9a3cfc7ed00271a6fa3"
#                             }
#                         }
#                     }],
#                     "must": [
#                     {
#                         "match_phrase":
#                         {
#                             "sources.level2":
#                             {
#                                 "query": "protocol"
#                             }
#                         }
#                     }]
#                 }
#             },
#             "random_score":
#             {}
#         }
#     }
# }

FILES = [
	'lfi.json',
	'paranoid.json',
	'php_eval.json',
	'protocol.json',
	'rfi.json',
	'security_scanner.json',
	'shell_injection.json',
	'sql_injection.json',
	'xss.json']

def _get_recursively(key, value, field, field_value):
	if field is not None and key == field:
		return True

	elif isinstance(value, dict):
		if get_recursively(value, field, field_value):
			return True

	elif isinstance(value, list):
		for item in value:
			if isinstance(item, dict) or isinstance(item, list):
				if get_recursively(item, field, field_value):
					return True
			elif field_value is not None and value == field_value:
				return True

	elif field_value is not None and value == field_value:
		return True


def get_recursively(search_dict, field, field_value):

	if isinstance(search_dict, dict):
		for key, value in search_dict.items():
			_get_recursively(key, value, field, field_value)
	else:
		for value in search_dict:
			_get_recursively(None, value, field, field_value)
	
	return False

for file in FILES:
	all_requests = []

	print('Processing ' + file)
	with open('json/' + file) as f:
		data = json.load(f)

	for hit in data['hits']['hits']:
		request = hit['_source']['request']
		request['_id'] = hit['_id']

		if 'isRevealReplayed' in request and request['isRevealReplayed']:
			continue

		new_headers = {}
		if hit['_source']['request']['headers']:
			for header in hit['_source']['request']['headers']:
				header[0].lower()
				new_headers[header[0]] = header[1]

		if 'user_agent' in request:
			new_headers['user-agent'] = request['user_agent']
			del request['user_agent']

		if 'referer' in request:
			new_headers['Referer'] = request['referer']
			del request['referer']
	
		request['headers'] = new_headers

		for waf_data in hit['_source']['infos']['waf_data']:
			new_request = request
			try:
				_filter = waf_data['filter'][0]
				if 'resolved_value' not in _filter and _filter['operator'][0] == '!':
					all_requests.append(new_request)
					continue

				value_trigger = _filter['resolved_value']
				ba = _filter['binding_accessor']
			except Exception as e:
				print(file, hit)
				raise

			if value_trigger == '<Redacted by Sqreen>':
				continue

			if ba.startswith('#.filtered_request_params') or ba.startswith('#.Request.FilteredParams') or ba.startswith('#.request_params'):
				is_val = value_trigger if ba.endswith('flat_values') else None
				is_key = value_trigger if ba.endswith('flat_keys') else None
				if not get_recursively(new_request['parameters'], is_key, is_val):
					if is_key:
						new_request['parameters'][is_key] = 'target'
					else:
						new_request['parameters']['target'] = is_val

			elif ba in ["#.args[0].@requestHeaderMap['user-agent']", "#.client_user_agent", "#.sess['headers']['user-agent']", "#._server['HTTP_USER_AGENT']", "#.client_user_agent"]:
				if value_trigger != new_headers['user-agent']:
					new_headers['User-Agent'] = value_trigger

			elif ba in ["#.request_uri", "#.Request.URL.RequestURI"]:
				new_request['path'] = value_trigger

			else:
				ok = False
				for headername in ["#.Request.Header | flat_", "#.Request.Headers | flat_", "#.request_headers | flat_", "#.args[0].@requestHeaderMap | flat_", "#.http_headers | flat_", "#.sess['headers'] | flat_"]:
					if ba.startswith(headername):
						is_val = value_trigger if ba.endswith('flat_values') else None
						is_key = value_trigger if ba.endswith('flat_keys') else None
						if not get_recursively(new_request['headers'], is_key, is_val):
							if is_key:
								new_request['headers'][is_key] = 'target'
							else:
								new_request['headers']['target'] = is_val
						ok = True
						break

			new_request['attack'] = value_trigger
			all_requests.append(new_request)

	with open('json/parsed_' + file, 'w+') as f:
		print('Total of {} items'.format(len(all_requests)))
		json.dump(all_requests, f, indent=1)
