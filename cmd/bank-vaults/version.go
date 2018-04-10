package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

const appName = "bank-vaults"
const version = "v0.0.1"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: fmt.Sprint("Print the version number of ", appName),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s %s\n", appName, version)
	},
}
