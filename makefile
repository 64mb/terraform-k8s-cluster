THIS_FILE := $(lastword $(MAKEFILE_LIST))
.PHONY: \
deploy \
deploy-only-sg 

deploy:
	./script/deploy.sh

deploy-only-sg:
	./script/deploy.sh -target=module.k8s_sg

