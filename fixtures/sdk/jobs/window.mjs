// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
function exactNano(value){
 if(typeof value!=="string"||!/^(0|-?[1-9][0-9]{0,18})$/.test(value))throw Error("invalid_fixture_clock");
 const nano=BigInt(value);if(nano< -9223372036854775808n||nano>9223372036854775807n||String(nano)!==value)throw Error("invalid_fixture_clock");return nano;
}
/** Fixture read window only; native C05 remains strictly [start,end). */
export function exclusiveCaptureEnd(realEnd,records){
 let end=exactNano(realEnd);
 for(const record of records){const observed=exactNano(record.observed_at_ns);if(observed===9223372036854775807n)throw Error("fixture_window_exhausted");if(observed>=end)end=observed+1n;}
 return String(end);
}
