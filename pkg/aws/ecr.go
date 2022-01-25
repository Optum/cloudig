package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
)

// ECRSVC is a wrapper for ECR Image Scan API calls
type ECRSVC interface {
	GetECRImagesWithTag(tag string) (map[string][]*ecr.ImageDetail, error)
	GetECRImageScanFindings(*ecr.ImageDetail) map[string]int64
}

// GetECRImagesWithTag finds all ECR images with a given tag. If no tag specified, all tagged images are returned
func (client *Client) GetECRImagesWithTag(tag string) (map[string][]*ecr.ImageDetail, error) {
	var reposNextToken *string
	var imagesNextToken *string
	images := make(map[string][]*ecr.ImageDetail)

	for {
		reposResp, err := client.ECR.DescribeRepositories(&ecr.DescribeRepositoriesInput{
			NextToken: reposNextToken,
		})

		if err != nil {
			return nil, err
		}

		for _, repo := range reposResp.Repositories {
			for {
				imagesResp, err := client.ECR.DescribeImages(&ecr.DescribeImagesInput{
					NextToken:      imagesNextToken,
					RegistryId:     repo.RegistryId,
					RepositoryName: repo.RepositoryName,
					Filter: &ecr.DescribeImagesFilter{
						TagStatus: aws.String("TAGGED"),
					},
				})

				if err != nil {
					return nil, err
				}

				// Find images matching a given tag. If no tag specified, return all tagged images
				if tag != "" {
					for _, image := range imagesResp.ImageDetails {
						if Contains(aws.StringValueSlice(image.ImageTags), tag) {
							images[*repo.RepositoryUri] = append(images[*repo.RepositoryUri], image)
						}
					}
				} else {
					images[*repo.RepositoryUri] = append(images[*repo.RepositoryUri], imagesResp.ImageDetails...)
				}

				imagesNextToken = imagesResp.NextToken
				if imagesNextToken == nil {
					break
				}
			}
		}

		reposNextToken = reposResp.NextToken
		if reposNextToken == nil {
			break
		}
	}

	return images, nil
}

func (client *Client) GetECRImageScanFindings(image *ecr.ImageDetail) map[string]int64 {
	if image != nil {
		scanFindings, err := client.ECR.DescribeImageScanFindings(&ecr.DescribeImageScanFindingsInput{
			ImageId: &ecr.ImageIdentifier{
				ImageDigest: image.ImageDigest,
			},
			RegistryId:     image.RegistryId,
			RepositoryName: image.RepositoryName,
		})
		if err != nil {
			return nil
		}
		if scanFindings != nil && scanFindings.ImageScanStatus != nil {
			return aws.Int64ValueMap(scanFindings.ImageScanFindings.FindingSeverityCounts)
		}
	}
	return nil
}
