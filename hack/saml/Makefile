.PHONY: keys
keys:
	openssl req -x509 -newkey rsa:2048 \
	  -keyout sp.key -out sp.crt \
	  -nodes -days 365 -subj "/CN=tikti-sp"
	chmod 0600 sp.key sp.crt
