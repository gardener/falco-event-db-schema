IMAGE_REPOSITORY   := europe-docker.pkg.dev/gardener-project/snapshots/i573718/falco-event-db-schema
IMAGE_TAG          := 0.0.1

.PHONY: build
build:
	docker build -t $(IMAGE_REPOSITORY):$(IMAGE_TAG) --rm .

.PHONY: push
push: build
	docker push $(IMAGE_REPOSITORY):$(IMAGE_TAG)
