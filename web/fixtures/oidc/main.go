// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// This local acceptance provider performs one-use code exchange with S256 PKCE.
package main

import (
 "crypto"
 "crypto/rand"
 "crypto/rsa"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "flag"
 "log"
 "net/http"
 "net/url"
 "sync"
 "time"
)
type pending struct { nonce, challenge, redirect, subject, issuer string; expires time.Time }
func main() {
 listen:=flag.String("listen","127.0.0.1:9443","HTTPS listen")
 issuer:=flag.String("issuer","https://localhost:9443","trusted HTTPS issuer")
 cert:=flag.String("tls-cert","","trusted certificate")
 keyFile:=flag.String("tls-key","","private key")
 callback:=flag.String("callback","https://localhost:8443/api/v1/oidc/callback","exact registered redirect")
 flag.Parse()
 if *cert=="" || *keyFile=="" {log.Fatal("trusted TLS certificate and key required")}
 key,err:=rsa.GenerateKey(rand.Reader,2048);if err!=nil{log.Fatal(err)}
 var lock sync.Mutex; codes:=map[string]pending{}
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /.well-known/openid-configuration",func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");_ =json.NewEncoder(w).Encode(map[string]any{"issuer":*issuer,"authorization_endpoint":*issuer+"/authorize","token_endpoint":*issuer+"/token","jwks_uri":*issuer+"/keys","response_types_supported":[]string{"code"},"subject_types_supported":[]string{"public"},"id_token_signing_alg_values_supported":[]string{"RS256"}})})
 mux.HandleFunc("GET /keys",func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");_=json.NewEncoder(w).Encode(map[string]any{"keys":[]any{map[string]string{"kty":"RSA","kid":"fixture","use":"sig","alg":"RS256","n":base64.RawURLEncoding.EncodeToString(key.N.Bytes()),"e":"AQAB"}}})})
 mux.HandleFunc("GET /authorize",func(w http.ResponseWriter,r *http.Request){
  q:=r.URL.Query();if q.Get("client_id")!="soundpost-browser"||q.Get("redirect_uri")!=*callback||q.Get("response_type")!="code"||q.Get("code_challenge_method")!="S256"||q.Get("nonce")==""||q.Get("state")=="" {http.Error(w,"invalid authorization request",400);return}
  w.Header().Set("Cache-Control","no-store");w.Header().Set("Content-Type","text/html; charset=utf-8");w.Header().Set("Referrer-Policy","no-referrer")
  _,_=w.Write([]byte(`<!doctype html><html lang="en"><title>Soundpost test identity provider</title><h1>Local identity provider</h1><form method="post"><label>Fixture identity<select name="identity"><option value="mapped">Explicitly mapped account</option><option value="unmapped">Unmapped email domain</option><option value="wrong-issuer">Wrong issuer</option></select></label><button>Authorize fixture account</button></form></html>`))
 })
 mux.HandleFunc("POST /authorize",func(w http.ResponseWriter,r *http.Request){
  if err:=r.ParseForm();err!=nil{http.Error(w,"invalid",400);return};q:=r.URL.Query();if q.Get("client_id")!="soundpost-browser"||q.Get("redirect_uri")!=*callback||q.Get("code_challenge_method")!="S256" {http.Error(w,"invalid",400);return}
  subject,claimIssuer:="mapped-subject",*issuer;switch r.PostForm.Get("identity"){case "unmapped":subject="unmapped-subject";case "wrong-issuer":claimIssuer="https://foreign.example.test";case "mapped":default:http.Error(w,"invalid identity",400);return}
  raw:=make([]byte,32);if _,err:=rand.Read(raw);err!=nil{http.Error(w,"unavailable",503);return};code:=hex.EncodeToString(raw)
  lock.Lock();codes[code]=pending{q.Get("nonce"),q.Get("code_challenge"),*callback,subject,claimIssuer,time.Now().Add(time.Minute)};lock.Unlock()
  target,_:=url.Parse(*callback);v:=target.Query();v.Set("code",code);v.Set("state",q.Get("state"));target.RawQuery=v.Encode();http.Redirect(w,r,target.String(),http.StatusSeeOther)
 })
 mux.HandleFunc("POST /token",func(w http.ResponseWriter,r *http.Request){
  if err:=r.ParseForm();err!=nil{http.Error(w,"invalid",400);return};lock.Lock();p,ok:=codes[r.Form.Get("code")];delete(codes,r.Form.Get("code"));lock.Unlock();digest:=sha256.Sum256([]byte(r.Form.Get("code_verifier")))
  if !ok||time.Now().After(p.expires)||r.Form.Get("redirect_uri")!=p.redirect||base64.RawURLEncoding.EncodeToString(digest[:])!=p.challenge||r.Form.Get("grant_type")!="authorization_code" {http.Error(w,"invalid code",401);return}
  header,_:=json.Marshal(map[string]string{"alg":"RS256","kid":"fixture"});claims,_:=json.Marshal(map[string]any{"iss":p.issuer,"sub":p.subject,"aud":"soundpost-browser","nonce":p.nonce,"exp":time.Now().Add(time.Minute).Unix(),"iat":time.Now().Unix(),"email":"account@unmapped.example.test"});input:=base64.RawURLEncoding.EncodeToString(header)+"."+base64.RawURLEncoding.EncodeToString(claims);hash:=sha256.Sum256([]byte(input));signature,err:=rsa.SignPKCS1v15(rand.Reader,key,crypto.SHA256,hash[:]);if err!=nil{http.Error(w,"unavailable",503);return};w.Header().Set("Content-Type","application/json");w.Header().Set("Cache-Control","no-store");_=json.NewEncoder(w).Encode(map[string]string{"access_token":"fixture-only","token_type":"Bearer","id_token":input+"."+base64.RawURLEncoding.EncodeToString(signature)})
 })
 server:=&http.Server{Addr:*listen,Handler:mux,ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:10*time.Second}
 log.Fatal(server.ListenAndServeTLS(*cert,*keyFile))
}
