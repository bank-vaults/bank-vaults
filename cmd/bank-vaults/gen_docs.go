// Copyright © 2023 Bank-Vaults Maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// NOTE: This is a development-only command that can only be executed using Makefile.

//go:build gen_docs
// +build gen_docs

package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"path"
	"path/filepath"
	"strings"
)

var genDocsCmd = &cobra.Command{
	Use:    "gen-docs",
	Hidden: true,
	Short:  "Generate documentation and save to an existing directory",
	Args:   cobra.ExactArgs(1), // requires path to output dir
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDir := args[0] // it is up to the caller to ensure this dir exists

		// _ = doc.GenMarkdown(rootCmd, os.Stdout)
		const fmTemplate = `---
title: %s
generated_file: true
---
`

		// Customized Hugo output based on https://github.com/spf13/cobra/blob/master/doc/md_docs.md
		filePrepender := func(filename string) string {
			name := filepath.Base(filename)
			base := strings.TrimSuffix(name, path.Ext(name))
			return fmt.Sprintf(fmTemplate, strings.Replace(base, "_", " ", -1))
		}
		linkHandler := func(name string) string {
			return name
		}
		c := rootCmd.Root()
		c.DisableAutoGenTag = true
		err := doc.GenMarkdownTreeCustom(c, outputDir, filePrepender, linkHandler)
		if err != nil {
			return err
		}

		logrus.Infof("Successfully generated and saved docs to dir=%s", outputDir)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(genDocsCmd)
}
