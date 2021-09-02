protocol: proto/keyexchange.proto proto/authentication.proto proto/mercury.proto proto/metadata.proto
	protoc -I=proto --python_out=proto $^