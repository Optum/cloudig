package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	awslocal "github.com/Optum/cloudig/pkg/aws"
	"github.com/Optum/cloudig/pkg/cloudig"

	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
)

var (
	commentsFile          string
	roleARN               string
	output                string
	region                string
	pastDays              string
	healthExcludeRegions  string
	healthIncludeRegions  string
	details               bool
	ecrImageTag           string
	identityARNs          string
	identityTags          string
	includeUsage          bool
	includeErrors         bool
	includeCallerIdentity bool
	absoluteTime          string
	relativeTime          int
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:       "get trustedadvisor/awsconfig/inspector/health/ecrscan",
	Short:     "Get report findings",
	ValidArgs: []string{"trustedadvisor", "awsconfig", "inspector", "health", "ecrscan"},
	Args:      cobra.OnlyValidArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("missing subcommands")
			os.Exit(1)
		}
	},
}

// reflectCmd represents the reflect command
var reflectCmd = &cobra.Command{
	Use:       "reflect iam",
	Short:     "Reflect on IAM role permissions",
	ValidArgs: []string{"iam"},
	Args:      cobra.OnlyValidArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("missing subcommands")
			os.Exit(1)
		}
	},
}

// trustedAdvisorCmd represents the get trustedadvisor command
var trustedAdvisorCmd = &cobra.Command{
	Use:     "trustedadvisor",
	Short:   "Get AWS Trusted Advisor report findings",
	Aliases: []string{"ta", "t"},

	Run: func(cmd *cobra.Command, args []string) {
		execute(&cloudig.TrustedAdvisorReport{})
	},
}

// awsConfigCmd represents the config command
var awsConfigCmd = &cobra.Command{
	Use:     "awsconfig",
	Short:   "Get AWS Config report findings",
	Aliases: []string{"ac", "a"},

	Run: func(cmd *cobra.Command, args []string) {
		execute(&cloudig.ConfigReport{})
	},
}

// inspectorCmd represents the inspector command
var inspectorCmd = &cobra.Command{
	Use:     "inspector",
	Short:   "Get AWS Inspector report findings",
	Aliases: []string{"inspect", "ins", "i"},

	Run: func(cmd *cobra.Command, args []string) {
		execute(&cloudig.InspectorReports{Helper: &cloudig.InspectorHelper{}})
	},
}

// healthCmd represents the get health command
var healthCmd = &cobra.Command{
	Use:     "health",
	Short:   "Get AWS Health notifications' details",
	Aliases: []string{"he", "h", "healthnotifications", "healthnotification"},

	Run: func(cmd *cobra.Command, args []string) {
		excludeRegionsArr := strings.Split(healthExcludeRegions, ",")
		if healthExcludeRegions == "" {
			excludeRegionsArr = []string{}
		}
		includeRegionsArr := strings.Split(healthIncludeRegions, ",")
		if healthIncludeRegions == "" {
			includeRegionsArr = []string{}
		}
		flags := struct {
			Details        bool
			PastDays       string
			ExcludeRegions []string
			IncludeRegions []string
		}{
			Details:        details,
			PastDays:       pastDays,
			ExcludeRegions: excludeRegionsArr,
			IncludeRegions: includeRegionsArr,
		}

		execute(&cloudig.HealthReport{
			Flags: flags,
		})
	},
}

// ecrScanCmd represents the ecrscan command
var ecrScanCmd = &cobra.Command{
	Use:     "ecrscan",
	Short:   "Get ECR Image Scan report findings",
	Aliases: []string{"scan", "sc", "s"},
	Run: func(cmd *cobra.Command, args []string) {
		execute(&cloudig.ImageScanReports{
			Flags: cloudig.ImageScanReportFlags{
				Tag:    ecrImageTag,
				Region: region,
			},
		})
	},
}

// iamCmd represents the reflect IAM command
var iamCmd = &cobra.Command{
	Use:     "iam",
	Short:   "Reflect on IAM Role permissions",
	Aliases: []string{"i", "iamrole"},

	Run: func(cmd *cobra.Command, args []string) {

		var roles []string
		if identityARNs != "" {
			roles = strings.Split(identityARNs, ",")
		}

		// convert string "k1:v1,k2:v2" to map[string]string{"k1":"v1","k2":"v2"}
		tags := make(map[string]string)
		for _, v := range strings.Split(identityTags, ",") {
			kv := strings.Split(v, ":")
			if len(kv) == 2 {
				tags[kv[0]] = kv[1]
			}
		}

		// if -u or -e is not provided both will be true, if one of them is provided then the other one is false
		if !includeUsage && !includeErrors {
			includeUsage = true
			includeErrors = true
		}

		// validate absolute-time
		if absoluteTime != "" {
			var startTime, endTime time.Time
			errorMessage := "--absolute-time is wrong. It should be in the form 'startTime-endTime' 'mm/dd/yyyy-mm/dd/yyy' ex: '10/25/2020-10/31/2020'"
			dates := strings.Split(absoluteTime, "-")
			if len(dates) != 2 {
				fmt.Println(errorMessage)
				os.Exit(1)
			}
			startDate, endDate := dates[0], dates[1]
			format := "01/02/2006" // mm/dd/yyyy format
			var err error
			// convert to time
			startTime, err = time.Parse(format, startDate)
			if err != nil {
				fmt.Println(errorMessage)
				os.Exit(1)
			}
			endTime, err = time.Parse(format, endDate)
			if err != nil {
				fmt.Println(errorMessage)
				os.Exit(1)
			}
			if endTime.Before(startTime) {
				fmt.Println(errorMessage)
				os.Exit(1)
			}
		}

		execute(&cloudig.ReflectReport{
			Flags: cloudig.NewReflectFlags(region, roles, tags, includeUsage, includeErrors, includeCallerIdentity, absoluteTime, relativeTime),
		})

	},
}

func init() {
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(reflectCmd)

	getCmd.AddCommand(trustedAdvisorCmd)
	getCmd.AddCommand(awsConfigCmd)
	getCmd.AddCommand(inspectorCmd)
	getCmd.AddCommand(healthCmd)
	getCmd.AddCommand(ecrScanCmd)
	reflectCmd.AddCommand(iamCmd)

	// Here you will define your flags and configuration settings.
	rootCmd.PersistentFlags().StringVarP(&commentsFile, "cfile", "c", "comments.yaml", "Comments file name")
	rootCmd.PersistentFlags().StringVar(&roleARN, "rolearn", "", "One or more role ARNs seperated by a comma [,]")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "json", "Output of report. Options: [json, table, mdtable]. Default output is JSON")
	rootCmd.PersistentFlags().StringVarP(&region, "region", "r", "us-east-1", "AWS region to get results from")
	rootCmd.PersistentFlags().IntVarP(&logger.Level, "verbose", "v", 3, "set log level, use 0 to silence, 1 for critical, 2 for warning, 3 for informational, 4 for debugging and 5 for debugging with AWS debug logging (default 3)")
	// this is CLI , so turning of timestamp
	logger.Timestamps = false
	// healthCmd specific flags
	healthCmd.PersistentFlags().BoolVarP(&details, "details", "d", false, "Flag to indicate level of printing for each notification (default false)")
	healthCmd.PersistentFlags().StringVar(&pastDays, "pastdays", "", "Number of past days to get results from")
	healthCmd.PersistentFlags().StringVar(&healthExcludeRegions, "exclude-regions", "", "Set of regions separated by [,] to exclude Health Notifications from. Takes precedence over include-regions")
	healthCmd.PersistentFlags().StringVar(&healthIncludeRegions, "include-regions", "", "Set of regions separated by [,] to include Health Notifications from. Use \"global\" as a region if wanting notifications affecting all regions. Ignored when exclude-regions is set")

	// ecrScanCmd specific flags
	ecrScanCmd.PersistentFlags().StringVar(&ecrImageTag, "tag", "", "Tag of ECR image(s) to report scan results.")

	// iamCmd specific flags
	iamCmd.PersistentFlags().StringVarP(&identityARNs, "identity", "i", "", "One or more IAM Identities (users, groups, and roles) ARNs separated by a comma [,].Only role ARNs is supported today")
	iamCmd.PersistentFlags().StringVarP(&identityTags, "identity-tags", "t", "", "Set of tags in form [key:value] separated by [,] to find the targeted IAM Identities. Only role ARN is supported today. Ignored when --identity is provided")
	// if -u or -e is not provided both will be true, if one of them is provided then the other one is false
	iamCmd.PersistentFlags().BoolVarP(&includeUsage, "usage", "u", false, "Reflect Identity usage data (default true, if --errors/-e is not explicitly provided)")
	iamCmd.PersistentFlags().BoolVarP(&includeErrors, "errors", "e", false, "Reflect Identity error data (default true, if --usage/-u is not explicitly provided)")
	iamCmd.PersistentFlags().BoolVar(&includeCallerIdentity, "caller-identity", false, "Include caller identity with the report(default false)")
	iamCmd.PersistentFlags().StringVar(&absoluteTime, "absolute-time", "", "Specify both the start and end times for the time filter in the form 'startTime-endTime' 'mm/dd/yyyy-mm/dd/yyy' ex: '10/25/2020-10/31/2020'")
	iamCmd.PersistentFlags().IntVar(&relativeTime, "relative-time", 1, "Specify a time filter relative to the current time in days. Default 1 day. Ignored when absolute-time is provided")
}

func execute(report cloudig.Report) {
	sess, err := awslocal.NewAuthenticatedSession(region)
	if err != nil {
		logger.Critical("error creating aws session: %v", err)
		os.Exit(1)
	}

	// example type should be "*cloudig.HealthReport", we are spliting the string to get "HealthReport"
	rType := strings.Split(fmt.Sprintf("%T", report), ".")[1]
	logger.Debug("all root level flags:\ncommentsFile: %s\nroleARN: %s\noutput: %s\nregion: %s\nlogLevel: %d\n", commentsFile, roleARN, output, region, logger.Level)

	if rType == "HealthReport" {
		logger.Debug("all health command flags:\ndetails: %t\npastDays: %s\n", details, pastDays)
	}
	if rType == "ReflectReport" {
		logger.Debug("all reflect command flags:\nidentityARNs: %s\nidentityTags: %s\nincludeUsage: %t\nincludeErrors: %t\nincludeCallerIdentity: %t\nabsoluteTime: %s\nrelativeTime: %d\n", identityARNs, identityTags, includeUsage, includeErrors, includeCallerIdentity, absoluteTime, relativeTime)
	}

	err = cloudig.ProcessReport(sess, report, output, commentsFile, roleARN)
	if err != nil {
		logger.Critical("error creating '%s': %v", rType, err)
	}
}
