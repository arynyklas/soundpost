// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
)

// ArtifactReadRequest is the closed read arm of the own C11 artifact endpoint.
// Private source bytes require the separate sources operation and grant.
type ArtifactReadRequest struct {
	Operation string   `json:"operation"`
	Org       model.ID `json:"org"`
	Project   model.ID `json:"project"`
	ID        model.ID `json:"id"`
}

func artifactCredential(s *auth.Service, w http.ResponseWriter, r *http.Request) (auth.Credential, error) {
	if len(r.Header.Values("Authorization")) != 0 {
		return AuthenticateRequest(s, r)
	}
	return protected(s, w, r)
}
func RegisterArtifactRoutes(mux *http.ServeMux, authorizer *auth.Service, service *artifacts.Service) {
	mux.HandleFunc("POST /api/v1/artifacts", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authorizer, w, r)
		if err != nil {
			artifactReply(w, nil, err)
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			artifactReply(w, nil, model.Fail(model.Invalid))
			return
		}
		switch media {
		case "application/json":
			r.Body = http.MaxBytesReader(w, r.Body, 65536)
			raw, readErr := io.ReadAll(r.Body)
			var q ArtifactReadRequest
			if readErr != nil || model.StrictJSON(raw, &q) != nil {
				artifactReply(w, nil, model.Fail(model.Invalid))
				return
			}
			if q.Operation != "read" && q.Operation != "sources" || q.Org == (model.ID{}) || q.Project == (model.ID{}) || q.ID == (model.ID{}) {
				artifactReply(w, nil, model.Fail(model.Invalid))
				return
			}
			scope, err := authorizer.Authorize(r.Context(), credential, q.Org, []model.ID{q.Project}, auth.ArtifactRead)
			if err != nil {
				artifactReply(w, nil, err)
				return
			}
			artifact, err := service.Lookup(r.Context(), scope, q.ID)
			if err != nil {
				artifactReply(w, nil, err)
				return
			}
			var stream io.ReadCloser
			receipt := artifact.Map
			if q.Operation == "sources" {
				if artifact.Sources == nil {
					artifactReply(w, nil, model.Fail(model.NotFound))
					return
				}
				receipt = *artifact.Sources
				stream, err = service.GetSources(r.Context(), scope, q.ID)
			} else {
				stream, err = service.Get(r.Context(), scope, q.ID)
			}
			if err != nil {
				artifactReply(w, nil, err)
				return
			}
			defer stream.Close()
			buffer := make([]byte, model.ArtifactFragmentLimit)
			n, readErr := stream.Read(buffer)
			if readErr != nil && readErr != io.EOF {
				artifactReply(w, nil, readErr)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", `attachment; filename="`+q.ID.String()+`.json"`)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Length", strconv.FormatUint(uint64(receipt.Manifest.Size), 10))
			w.Header().Set("ETag", `"`+receipt.Hash.String()+`"`)
			if n > 0 {
				if _, err = w.Write(buffer[:n]); err != nil {
					return
				}
			}
			if readErr == io.EOF {
				return
			}
			for {
				n, err = stream.Read(buffer)
				if n > 0 {
					if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
						return
					}
				}
				if err != nil {
					if err != io.EOF {
						panic(http.ErrAbortHandler)
					}
					return
				}
			}
		case "multipart/form-data":
			r.Body = http.MaxBytesReader(w, r.Body, model.ArtifactBundleLimit+(64<<10))
			parts, err := r.MultipartReader()
			if err != nil {
				artifactReply(w, nil, model.Fail(model.Invalid))
				return
			}
			part, err := parts.NextPart()
			if err != nil || part.FormName() != "manifest" {
				artifactReply(w, nil, model.Fail(model.Invalid))
				return
			}
			raw, err := io.ReadAll(io.LimitReader(part, 16385))
			part.Close()
			var manifest artifacts.Manifest
			if err != nil || len(raw) > 16384 || model.StrictJSON(raw, &manifest) != nil {
				artifactReply(w, nil, model.Fail(model.Invalid))
				return
			}
			if err = artifacts.ValidateManifest(manifest); err != nil {
				artifactReply(w, nil, err)
				return
			}
			scope, err := authorizer.Authorize(r.Context(), credential, manifest.Org, []model.ID{manifest.Project}, auth.ArtifactWrite)
			if err != nil {
				artifactReply(w, nil, err)
				return
			}
			maxBytes, _, err := scope.ArtifactPolicy(r.Context(), manifest.Project, manifest.Source, manifest.Build, manifest.SourceContent)
			if err != nil {
				artifactReply(w, nil, err)
				return
			}
			// Refuse before spooling the body to disk (Put enforces it too).
			if uint64(manifest.Size) > maxBytes {
				artifactReply(w, nil, model.Fail(model.TooLarge))
				return
			}
			part, err = parts.NextPart()
			if err != nil || part.FormName() != "file" {
				artifactReply(w, nil, model.Fail(model.Invalid))
				return
			}
			// The file part streams straight into Put: nothing is spooled to disk, and
			// Put admits (size ceiling, in-flight memory budget) before it reads a byte.
			artifact, err := service.Put(r.Context(), scope, manifest, &filePart{part: part, parts: parts})
			artifactReply(w, artifact, err)
		default:
			artifactReply(w, nil, model.Fail(model.Invalid))
		}
	})
}

// artifactReply distinguishes a stale policy epoch/revision (409, so a client
// can re-resolve policy and resume) from malformed input; every other fault
// keeps the shared mapping.
func artifactReply(w http.ResponseWriter, v any, e error) {
	var f *model.Fault
	if errors.As(e, &f) && (f.Code == model.Stale || f.Code == model.Quota && f.Retryable) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		copy := *f
		if requestID, err := model.ParseID(w.Header().Get("X-Request-ID")); err == nil {
			copy.RequestID = requestID
		}
		status := http.StatusConflict
		if f.Code == model.Quota {
			// Upload admission is a retryable refusal, like the ingest quota.
			status = http.StatusTooManyRequests
			copy.Retryable = true
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(&copy)
		return
	}
	reply(w, v, e)
}

// filePart is the file part of an upload. At its end it requires that no other
// part follows, so a body with trailing parts fails inside Put's read, before
// anything is stored (Put maps a read error to Invalid).
type filePart struct {
	part  io.Reader
	parts *multipart.Reader
	err   error
}

func (f *filePart) Read(p []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err := f.part.Read(p)
	if err == io.EOF {
		next, nextErr := f.parts.NextPart()
		if nextErr != io.EOF {
			if next != nil {
				next.Close()
			}
			f.err = model.Fail(model.Invalid)
			return n, f.err
		}
	}
	return n, err
}
