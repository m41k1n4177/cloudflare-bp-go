# Go CloudFlare ByPass
[![tests](https://github.com/m41k1n4177/cloudflare-bp-go/actions/workflows/tests.yml/badge.svg)](https://github.com/m41k1n4177/cloudflare-bp-go/actions/workflows/tests.yml)
[![hosted tests](https://github.com/m41k1n4177/cloudflare-bp-go/actions/workflows/self.yml/badge.svg)](https://github.com/m41k1n4177/cloudflare-bp-go/actions/workflows/self.yml)


small round tripper to avoid triggering the "attention required" status of CloudFlare for HTTP requests.
It'll add required/validated headers on requests and update the client TLS configuration to pass the CloudFlare validation.

This is (at least so far) **NOT** intended to solve challenges provided by CloudFlare, only to prevent CloudFlare from directly displaying you a challenge on the first request.

The bypass is tested on a schedule everyday at 3 AM in case CloudFlare updated their detection, so the badge is always displaying if the bypass still works.

## Dependencies
- [eddycjy/fake-useragent](https://github.com/EDDYCJY/fake-useragent) - for setting a believable request user agent.
CloudFlare is relatively forgiving with the user agents anyways but it'll add some variety for the long term.

## Usage
You can add the round tripper as any other round tripper:
```go
client := &http.Client{}
client.Transport = cloudflarebp.AddCloudFlareByPass(client.Transport)
```

small notice:  
Using the http.DefaultTransport will currently still fail, nil or empty &http.Transport works.
Didn't have the time to check what exactly is different causing the CloudFlare validation to fail though.

## Development
Want to contribute? Great!  
I'm always glad hearing about bugs or pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
