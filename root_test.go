package gois

// func Test_RootHandler(t *testing.T) {
// 	l, err := NewListener(PkgRequests(
// 		"http://go.is/",
// 		"http://go.is/root",
// 		"http://go.benjiv.com/test",
// 		"http://go.benjiv.com/test2",
// 		"http://go.benjiv.com/test3",
// 		"http://go.benjiv.com/test4",
// 		"http://go.benjiv.com/test5",
// 		"http://dev.mydom.com/test",
// 		"http://example.com/test",
// 	)...)

// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	t.Fatal(http.Serve(l, http.HandlerFunc(RootHandler)))
// }

// func Test_Root_RequestHandler(t *testing.T) {

// 	req := httptest.NewRequest(http.MethodGet, "http://go.is/", nil)
// 	resp := httptest.NewRecorder()

// 	RootHandler(resp, req)

// 	if resp.Code != http.StatusOK {
// 		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.Code)
// 	}

// 	t.Log(resp.Body.String())

// 	// if resp.Body.String() != "Hello World" {
// 	// 	t.Errorf("expected body %s, got %s", "Hello World", resp.Body.String())
// 	// }
// }
