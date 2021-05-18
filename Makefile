VERSION=$(shell cat VERSION)
.PHONY: test

all: test build

build:
	go build -ldflags="-X github.com/Optum/cloudig/cmd.version=${VERSION}" -o cloudig

mocks:
	mockgen -destination=pkg/mocks/mock_ec2.go -package=mocks github.com/aws/aws-sdk-go/service/ec2/ec2iface EC2API
	mockgen -destination=pkg/mocks/mock_inspector.go -package=mocks github.com/aws/aws-sdk-go/service/inspector/inspectoriface InspectorAPI
	mockgen -destination=pkg/mocks/mock_trustedadvisor.go -package=mocks github.com/aws/aws-sdk-go/service/support/supportiface SupportAPI
	mockgen -destination=pkg/mocks/mock_awsconfig.go -package=mocks github.com/aws/aws-sdk-go/service/configservice/configserviceiface ConfigServiceAPI
	mockgen -destination=pkg/mocks/mock_sts.go -package=mocks github.com/aws/aws-sdk-go/service/sts/stsiface STSAPI
	mockgen -destination=pkg/mocks/mock_health.go -package=mocks github.com/aws/aws-sdk-go/service/health/healthiface HealthAPI
	mockgen -destination=pkg/mocks/mock_aws.go -package=mocks github.com/Optum/cloudig/pkg/aws APIs
	mockgen -destination=pkg/mocks/mock_ecr.go -package=mocks github.com/aws/aws-sdk-go/service/ecr/ecriface ECRAPI
	mockgen -destination=pkg/mocks/mock_cloudtrail.go -package=mocks github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface CloudTrailAPI
	mockgen -destination=pkg/mocks/mock_athena.go -package=mocks github.com/aws/aws-sdk-go/service/athena/athenaiface AthenaAPI
	mockgen -destination=pkg/mocks/mock_iam.go -package=mocks github.com/aws/aws-sdk-go/service/iam/iamiface IAMAPI

test:
	echo "Running tests"
	go clean -testcache
	go test -v -cover ./pkg/aws
	go test -v -cover ./pkg/cloudig

report:
	go clean -testcache
	go get -u github.com/jstemmer/go-junit-report
	mkdir -p reports
	go test -v -cover ./pkg/aws | tee /dev/tty | ${GOPATH}/bin/go-junit-report > reports/test_awspackage.xml
	go test -v -cover ./pkg/cloudig | tee /dev/tty | ${GOPATH}/bin/go-junit-report > reports/test_cloudigpackage.xml
	go mod tidy
	

compile:
	echo "Compiling for Linux, Windows, and Mac"
	env GOOS=linux GOARCH=amd64 go build -ldflags="-X github.com/Optum/cloudig/cmd.version=${VERSION}" -o cloudig_linux_amd64_${VERSION} main.go
	env GOOS=windows GOARCH=amd64 go build -ldflags="-X github.com/Optum/cloudig/cmd.version=${VERSION}" -o cloudig_windows_amd64_${VERSION} main.go
	env GOOS=darwin GOARCH=amd64 go build -ldflags="-X github.com/Optum/cloudig/cmd.version=${VERSION}" -o cloudig_darwin_amd64_${VERSION} main.go

clean:
	rm cloudig*
