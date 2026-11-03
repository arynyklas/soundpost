// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main
import("encoding/json";"errors";"fmt";"os";"strings";"testing";"soundpost/internal/auth";"soundpost/internal/model")
func TestSmokeFailureDiagnosticsNeverEchoUnderlyingContent(t *testing.T){
 const secret="CANARY_TOKEN_PASSWORD_RESPONSE_PRIVATE_PATH"
 for _,cause:=range []error{errors.New(secret),&os.PathError{Op:"open",Path:"/"+secret,Err:os.ErrPermission},model.Fail(model.Forbidden)}{
  diagnostic:=annotateSmokeFailure("bootstrap_scope","artifact_write",model.NewID(),cause)
  text:=fmt.Sprint(diagnostic)
  if strings.Contains(text,secret)||strings.Contains(text,"/"){t.Fatal("smoke diagnostic leaked underlying data")}
  if !strings.Contains(text,"smoke=bootstrap_scope")||!strings.Contains(text,"stage=artifact_write"){t.Fatal("diagnostic lost real boundary")}
 }
 failure:=httpSmokeFailure("bootstrap",503,200,[]byte(`{"code":"unavailable","detail":"`+secret+`"}`))
 text:=fmt.Sprint(failure)
 if strings.Contains(text,secret)||!strings.Contains(text,"code=unavailable")||!strings.Contains(text,"actual=503 expected=200"){t.Fatal("unsafe or incomplete HTTP diagnostic")}
 unknown:=httpSmokeFailure("bootstrap",500,200,[]byte(`{"code":"`+secret+`"}`))
 if strings.Contains(fmt.Sprint(unknown),secret){t.Fatal("untrusted fault code escaped allowlist")}
 _,encodeError:=json.Marshal(auth.AdminReadRequest{Kind:"organizations"})
 if encodeError==nil||classifySmokeError(encodeError)!="encode"{t.Fatal("pre-HTTP zero-ID marshal failure was not classified as encode")}
}
