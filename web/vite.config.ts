// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {defineConfig} from 'vite';
export default defineConfig({build:{outDir:'dist',emptyOutDir:true,sourcemap:false,target:'es2022'},server:{host:'127.0.0.1'}});
