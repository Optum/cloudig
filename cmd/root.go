package cmd

/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Makefile uses flags to set version variable
// Makefile version is the superior source of truth for versioning
// However if the make commands are run without this flags, this backup is used
var version = "local"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "cloudig [VERB] [NOUN] --FLAG",
	Long: `cloudig is a CLI tool that generates reports from various cloud sources and user-provided comments

Supported sources are:

* AWS Trusted Advisor: https://aws.amazon.com/premiumsupport/trustedadvisor/
* AWS Config:          https://aws.amazon.com/config/
* Amazon Inspector:    https://aws.amazon.com/inspector/
* AWS Health:          https://aws.amazon.com/premiumsupport/technology/personal-health-dashboard/
* AWS ECR:             https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
* AWS IAM Reflect:     https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html`,

	// Version is set at compile time in parallel to rootCmd, so we need to read version after
	Version: *(&version),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SetVersionTemplate("Beta release: {{ .Version }}\n")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
