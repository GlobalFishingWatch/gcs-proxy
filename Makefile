# If no arguments are given, use the gcloud setup
_user=$(shell google-cloud-sdk/bin/gcloud config list | grep account | sed -e "s+.*= ++g")
_application=$(shell google-cloud-sdk/bin/gcloud config list | grep project | sed -e "s+.*= ++g")
_version=$(shell git symbolic-ref HEAD | sed -e "s+refs/heads/++g")
_client_version=$(shell git rev-parse HEAD)


# Parse arguments
ifeq ($(user),)
	user=${_user}
else
	user=$(user)
endif
ifeq ($(application),)
	application=${_application}
else
	application=$(application)
endif
ifeq ($(version),)
	version=${_version}
else
	version=$(version)
endif
ifeq ($(shell whoami),vagrant)
	devhost=0.0.0.0
else
	devhost=127.0.0.1
endif

_test:
	echo ${user}
	echo ${application}
	echo ${version}


SHELL=/bin/bash

.PHONY: all apt-prerequisites prerequisites build gcloud deps gae/virtualenvloader/gaevirtualenv dependencies junk-clean upload clean dev-server

all: build

deps:
	test -e $@ || virtualenv $@
	unset VIRTUAL_ENV; source $@/bin/activate; pip install --upgrade pip; pip install -r requirements.txt

gae/virtualenvloader/gaevirtualenv:
	test -e $@ || virtualenv $@
	unset VIRTUAL_ENV; source $@/bin/activate; pip install --upgrade pip; pip install -r gae-requirements.txt

google_appengine/appcfg.py:
	curl -sLO https://storage.googleapis.com/appengine-sdks/featured/google_appengine_1.9.30.zip
	unzip -q google_appengine_1.9.30.zip
	rm google_appengine_1.9.30.zip

google-cloud-sdk/bin/gcloud google-cloud-sdk/bin/gsutil:
	curl -sLO https://dl.google.com/dl/cloudsdk/channels/rapid/google-cloud-sdk.tar.gz
	tar -xzf google-cloud-sdk.tar.gz; rm google-cloud-sdk.tar.gz
	cd google-cloud-sdk; ./install.sh --usage-reporting false --path-update false --command-completion false

dependencies: deps gae/virtualenvloader/gaevirtualenv google_appengine/appcfg.py google-cloud-sdk/bin/gcloud gae/server_secret.txt

gae/server_secret.txt:
	echo $(shell pwgen 16 1) > $@

apt-prerequisites:
	sudo apt-get update
	sudo apt-get install -y zip git python-pip python-virtualenv python-dev build-essential libffi-dev libmysqlclient-dev libssl-dev python-mysqldb libjpeg-dev

prerequisites: apt-prerequisites

junk-clean:
	find . -name "*.pyc" -o -name "*~" | while read name; do rm "$$name"; done

build: dependencies junk-clean

upload: google_appengine/appcfg.py build
	google_appengine/appcfg.py update -A $(application) -V $(version) gae
	# google-cloud-sdk/bin/gcloud preview app deploy ./gae/app.yaml --project "$(application)" --version "$(version)"

clean:
	rm -rf deps
	rm -rf gae/virtualenvloader/gaevirtualenv

upload-members: google_appengine/appcfg.py
	google_appengine/appcfg.py upload_data \
	  --config_file=./member-bulkloader.yaml \
	  --filename=./members.csv \
	  --kind=Member \
	  --num_threads=4 \
	  --url="http://$(application).appspot.com/_ah/remote_api" \
	  --rps_limit=500 \
	  --email=$(user)

dev-server: dependencies
	cd gae; export PATH="../google_appengine:$$PATH"; dev_appserver.py . --host $(devhost) -A $(_application) --datastore_path /tmp/dev_app_server_datastore --datastore_consistency_policy consistent

test: google_appengine/appcfg.py dependencies
	unset VIRTUAL_ENV; source deps/bin/activate; cd gae; nosetests --with-gae --gae-lib-root="../google_appengine"

deploy: build test upload
