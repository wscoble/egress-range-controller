/*
Copyright 2026 Greybeard Holdings LLC.

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

package ranges

import "testing"

func TestNormalizeDigestDiff(t *testing.T) {
	a := MustNormalize([]string{"185.70.42.7/24", "185.70.40.0/22", "185.70.40.0/22", " 10.0.0.1 "})
	want := "10.0.0.1/32,185.70.40.0/22,185.70.42.0/24"
	if got := join(a); got != want {
		t.Fatalf("got %s", got)
	}
	if Digest([]string{"185.70.42.0/24", "185.70.40.0/22"}) != Digest([]string{"185.70.40.0/22", "185.70.42.0/24"}) {
		t.Fatal("digest not order-independent")
	}
	add, rem := Diff([]string{"1.0.0.0/24", "2.0.0.0/24"}, []string{"2.0.0.0/24", "3.0.0.0/24"})
	if join(add) != "3.0.0.0/24" || join(rem) != "1.0.0.0/24" {
		t.Fatal(add, rem)
	}
	if f := ChangeFraction([]string{"1.0.0.0/24", "2.0.0.0/24"}, []string{"2.0.0.0/24", "3.0.0.0/24"}); f != 1.0 {
		t.Fatal(f)
	}
	if !Contains([]string{"185.70.40.0/22"}, "185.70.42.41") || Contains([]string{"185.70.40.0/22"}, "185.70.44.1") {
		t.Fatal("contains")
	}
	if _, err := Normalize([]string{"nope"}); err == nil {
		t.Fatal("expected error")
	}
	if got := join(FilterFamilies([]string{"2001:db8::/32", "192.0.2.0/24"}, []string{"IPv6"})); got != "2001:db8::/32" {
		t.Fatal(got)
	}
}

func join(x []string) string {
	s := ""
	for i, v := range x {
		if i > 0 {
			s += ","
		}
		s += v
	}
	return s
}
