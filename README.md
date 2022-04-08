# (GoIS) Go Import Server

## Description

The Go Import Server is a simple HTTP server which supplies meta tags for Go
packages so that they can be dynamically imported by Go programs using custom
import paths.

## Paths

### Go Get Execution

When Go executes a URL request it passes a query string of `go-get=1` to the
server. This is used to determine whether the server should return a meta tag
for the package.

### Standard Path Resolution

When an endpoint is resolved for a non-`go-get` request, the server will
redirect the caller to the package's documentation page or homepage as
configured.

## Configuration

Configuration is done via a json document.

```json

[
    {
        "domain": "example.com",
        "homepage": "https://example.com/test",
        "docs": "https://example.com/test/docs",
        "imports": [
            {
                "path": "github.com/example/test",
                "type:": "git",
                "url": "https://github.com/example/test.git"

            }
        ]
    },
    {
        "domain": "example2.com",
        "homepage": "https://example2.com/test",
        "docs": "https://example2.com/test/docs",
        "imports": [
            {
                "path": "github.com/example2/test",
                "type:": "git",
                "url": "https://github.com/example2/test.git"
                
            }
        ]
    }
]

```
