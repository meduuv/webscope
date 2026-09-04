# WebScope

WebScope is a website inspection CLI for checking transport security, DNS resolution, TLS certificate health and common HTTP security headers from one command.

## What it checks

* HTTP response status
* DNS-resolved addresses
* Negotiated TLS version
* Certificate expiration
* HSTS, CSP, X-Frame-Options and related headers
* Server header exposure
* Simple posture score for fast comparison
* JSON output for automation

## Install

```bash
git clone https://github.com/meduuv/webscope.git
cd webscope
pip install -e .
```

## Examples

```bash
webscope example.com
webscope https://example.com --json
```

Use WebScope only against sites you own or are permitted to assess. The tool performs ordinary DNS, TLS and HTTP requests and does not attempt exploitation.

## Development

```bash
python -m unittest discover -s tests -v
```

## Credits

Built by [meduuv](https://guns.lol/meduu).

## License

MIT
