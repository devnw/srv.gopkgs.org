package gois

var Config = `[
	{
		"domain": "vpn.benjiv.com",
		"imports": [
			{
				"path": "hammer",
				"type": "git",
				"repo": "https://benjiv.com/hammer",
				"website": "https://benjiv.com/hammer",
				"docs": "https://benjiv.com/hammer/docs"
			},
			{
				"path": "demo",
				"type": "git",
				"repo": "https://benjiv.com/demo",
			},
		]
	},
	{
		"domain": "i.devnw.com",
		"imports": [
			{
				"path": "alog",
				"type": "git",
				"repo": "https://devnw.com",
				"docs": "https://devnw.com/alog/docs"
			},
			{
				"path": "dns",
				"type": "git",
				"repo": "https://devnw.com/",
				"docs": "https://devnw.com/docs"
			},
		]
	},
	{
		"domain": "i.atomizer.io",
		"imports": [
			{
				"path": "engine",
				"type": "git",
				"repo": "https://atomizer.io/engine",
				"docs": "https://atomizer.io/docs"
			},
			{
				"path": "amqp",
				"type": "git",
				"repo": "https://atomizer.io",
				"docs": "https://atomizer.io/docs"
			},
		]
	}
]
`

// func RootHandler(w http.ResponseWriter, r *http.Request) {
// 	fmt.Printf("Request URI: %s\n", r.RequestURI)
// 	fmt.Printf("Remote Address: %s\n", r.RemoteAddr)

// 	h := strings.Split(r.Host, ":")
// 	if len(h) == 0 {
// 		panic("no host")
// 	}

// 	fmt.Println(h[0])

// 	// w.Write([]byte("Hello World"))

// 	ipath := "go.benjiv.com/testpath"
// 	repo := "https://github.com/benjivesterby/testpath"

// 	iurl, err := url.Parse(ipath)
// 	if err != nil {
// 		panic(err)
// 	}

// 	repoUrl, err := url.Parse(repo)
// 	if err != nil {
// 		panic(err)
// 	}

// 	data := Module{
// 		ImportPath: iurl,
// 		Proto:      Git,
// 		RepoURL:    repoUrl,
// 	}

// }
