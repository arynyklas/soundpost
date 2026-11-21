// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexp

import "context"

// checkedInput keeps cancellation state in the existing machine pool. Prefix
// skipping is disabled only on this cancellable NFA path, so long searches
// cannot disappear inside a non-interruptible string search.
type checkedInput struct {
 inputString
 ctx context.Context
 untilCheck uint16
}
func (i *checkedInput) canCheckPrefix() bool { return false }
func (i *checkedInput) step(pos int) (rune,int) {
 if i.untilCheck == 0 {
  if i.ctx.Err()!=nil { return endOfText,0 }
  i.untilCheck=256
 }
 i.untilCheck--
 return i.inputString.step(pos)
}

// ProgramSize is the conservative work factor used by the query budget.
func (re *Regexp) ProgramSize() uint64 {
 n:=uint64(len(re.prog.Inst))
 for _,inst:=range re.prog.Inst { n+=uint64(len(inst.Rune)) }
 return n
}
func (re *Regexp) CaptureSlots() int { return re.prog.NumCap }

// ExecuteContext uses the same pinned NFA program and leftmost-first capture
// rules as doExecute. It deliberately bypasses the onepass/backtrack shortcuts
// so all input scanning can be cancelled, without copying the input or regexp.
// pos is an absolute byte position in s, retaining anchor/boundary context.
func (re *Regexp) ExecuteContext(ctx context.Context,s string,pos,ncap int)([]int,error) {
 if err:=ctx.Err();err!=nil{return nil,err}
 m:=re.get()
 m.checked=checkedInput{inputString:inputString{str:s},ctx:ctx}
 m.init(ncap)
 matched:=m.match(&m.checked,pos)
 err:=ctx.Err()
 var out []int
 if matched && err==nil {
  out=arrayNoInts[:0:0]
  out=append(out,m.matchcap...)
 }
 m.checked=checkedInput{}
 re.put(m)
 return out,err
}
