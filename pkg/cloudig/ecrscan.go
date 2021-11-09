package cloudig

import (
	"strings"
	"time"

	awslocal "github.com/Optum/cloudig/pkg/aws"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/kris-nova/logger"
)

// ImageScanReports struct specify the format of scan reports
type ImageScanReports struct {
	Findings []ImageScanFindings  `json:"findings"`
	Flags    ImageScanReportFlags `json:"-"` // hide in json output
	jsonOutputHelper
}

// ImageScanReportFlags struct specify the format of passed in flags
type ImageScanReportFlags struct {
	Tag    string `json:"tag,omitempty"`
	Region string `json:"region"`
}

// ImageScanFindings struct specify the scan finding reports format
type ImageScanFindings struct {
	AccountID          string           `json:"accountId"`
	ImageDigest        string           `json:"imageDigest"`
	ImageTag           string           `json:"imageTag"`
	RepositoryName     string           `json:"repositoryName"`
	ImageFindingsCount map[string]int64 `json:"imageFindingsCount"`
	Comments           string           `json:"comments"`
	Region             string           `json:"region"`
}

// GetReport of the vulnerability count of the images of the builds
func (report *ImageScanReports) GetReport(client awslocal.APIs, comments []Comments) error {
	start := time.Now()

	// Get accountID from roleARN
	accountID, err := client.GetAccountID()
	if err != nil {
		return err
	}
	logger.Info("working on ECR Scan report for account: %s", accountID)

	// Get all images with a given tag
	if report.Flags.Tag != "" {
		logger.Info("finding all ECR images with tag: %s for account: %s in region: %s", report.Flags.Tag, accountID, report.Flags.Region)
	} else {
		logger.Info("finding all tagged ECR images for account: %s in region: %s", accountID, report.Flags.Region)
	}
	images, err := client.GetECRImagesWithTag(report.Flags.Tag)
	if err != nil {
		return err
	}

	// Create findings
	for repo, imageList := range images {
		// If a tag was specified there should only be one image returned per repo
		if report.Flags.Tag != "" && len(imageList) == 1 {
			scanFindingCountMap := convertScanFindings(imageList[0])
			if len(scanFindingCountMap) > 0 {
				imageURI := repo + ":" + report.Flags.Tag
				scanReport := ImageScanFindings{
					AccountID:          accountID,
					ImageDigest:        aws.StringValue(imageList[0].ImageDigest),
					ImageTag:           report.Flags.Tag,
					RepositoryName:     aws.StringValue(imageList[0].RepositoryName),
					ImageFindingsCount: scanFindingCountMap,
					Comments:           getComments(comments, accountID, findingTypeECRScan, imageURI),
					Region:             report.Flags.Region,
				}
				report.Findings = append(report.Findings, scanReport)
			}

		} else {
			//	Create finding for each tag
			for _, image := range imageList {
				scanFindingCountMap := convertScanFindings(image)
				if len(scanFindingCountMap) > 0 {
					imageURI := repo + ":" + aws.StringValueSlice(image.ImageTags)[0]
					scanReport := ImageScanFindings{
						AccountID:          accountID,
						ImageDigest:        aws.StringValue(image.ImageDigest),
						ImageTag:           strings.Join(aws.StringValueSlice(image.ImageTags), ","),
						RepositoryName:     aws.StringValue(image.RepositoryName),
						ImageFindingsCount: scanFindingCountMap,
						Comments:           getComments(comments, accountID, findingTypeECRScan, imageURI),
						Region:             report.Flags.Region,
					}
					report.Findings = append(report.Findings, scanReport)
				}

			}
		}
	}

	logger.Success("getting ECR Scan Results for account %s took %s", accountID, time.Since(start))
	return nil
}

func convertScanFindings(image *ecr.ImageDetail) map[string]int64 {
	if image != nil && image.ImageScanStatus != nil && aws.StringValue(image.ImageScanStatus.Status) == "COMPLETE" {
		return aws.Int64ValueMap(image.ImageScanFindingsSummary.FindingSeverityCounts)
	}
	return nil
}
