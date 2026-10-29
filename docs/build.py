"""Build the standalone GitHub Pages guide from the shareable HTML source."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
source = (ROOT / "src/guide.html").read_text(encoding="utf-8")
head, body = source.split("<!-- GUIDE_BODY -->", 1)
page = ('<!doctype html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        + head + '\n</head>\n<body>\n' + body + '\n</body>\n</html>\n')
(ROOT / "index.html").write_text(page, encoding="utf-8")
print("Built docs/index.html: %s bytes" % len(page.encode("utf-8")))
