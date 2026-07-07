import truststore

# Corporate networks often intercept TLS with their own root CA, which is
# trusted by Windows but not by Python's bundled certifi CA list. This makes
# requests/urllib3/httpx validate against the OS trust store instead, so
# GitHub, OpenAI, and OSV.dev calls succeed on such networks.
truststore.inject_into_ssl()
