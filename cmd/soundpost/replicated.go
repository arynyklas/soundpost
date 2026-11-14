// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"flag"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"os"
)

func openConfiguredCore(dir, mode, configuration string, nodeID uint64) (*appcore.App, error) {
	if mode == "single" {
		if configuration != "" || nodeID != 0 {
			return nil, model.Fail(model.Invalid)
		}
		return appcore.Open(dir)
	}
	if mode != "distributed" || configuration == "" || nodeID == 0 {
		return nil, model.Fail(model.Invalid)
	}
	raw, err := os.ReadFile(configuration)
	if err != nil {
		return nil, err
	}
	var config appcore.NodeConfig
	if model.StrictJSON(raw, &config) != nil || config.NodeID != nodeID {
		return nil, model.Fail(model.Invalid)
	}
	return appcore.OpenDistributed(dir, config)
}
func runClusterSeed(args []string) error {
	f := flag.NewFlagSet("cluster-seed", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("data-dir", "", "offline installation directory")
	out := f.String("output", "", "new private seed file")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *out == "" {
		return model.Fail(model.Invalid)
	}
	app, err := appcore.Open(*dir)
	if err != nil {
		return err
	}
	defer app.Close()
	return app.WriteClusterSeed(*out)
}
