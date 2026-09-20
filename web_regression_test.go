package main

import (
	"strings"
	"testing"
)

func TestBilingualUIHasNoReloadLoop(t *testing.T) {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, forbidden := range []string{"location.reload()", "location.reload("} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("reload-loop regression: UI contains %q", forbidden)
		}
	}
	for _, required := range []string{
		"function restoreDOM", "originalText=new WeakMap()", "id=\"topShutdown\"",
		"$('#topShutdown').onclick=exitApp", "document.documentElement.dir=currentLang==='ar'?'rtl':'ltr'",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("bilingual/exit regression: missing %q", required)
		}
	}
}

func TestVersionIsCurrent(t *testing.T) {
	if appVersion != "2.1.1" {
		t.Fatalf("unexpected version %s", appVersion)
	}
}
