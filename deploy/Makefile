# parameters for "build"
REPO              = https://github.com/avery-blanchard/container-integrity-measurement
BRANCH            = ebpf

# parameters for "publish" and "deploy"
REGISTRY          = 100.64.0.255:5000
TAG               = latest

all: build

build:
	@docker build . -t containermeter --build-arg="repo=${REPO}" --build-arg="branch=${BRANCH}"

publish: build
	@docker tag containermeter ${REGISTRY}/containermeter:${TAG} && \
	docker push ${REGISTRY}/containermeter:${TAG}

deploy:
	@cat containermeter.yml.in | \
	sed "s/%%registry%%/${REGISTRY}/" | \
	sed "s/%%tag%%/${TAG}/" | \
	kubectl apply -f -

undeploy:
	@cat containermeter.yml.in | \
	sed "s/%%registry%%/${REGISTRY}/" | \
	sed "s/%%tag%%/${TAG}/"  | \
	kubectl delete -f -
