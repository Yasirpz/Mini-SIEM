"""
Render a Markdown document to a print-quality PDF.

Converts Markdown to styled HTML, then uses headless Chrome (or Edge) to
print it. Chrome's print engine is used rather than a Python PDF library
because it handles page breaks, widow/orphan control and table splitting
properly, which matters for a document of thesis length.

Usage:
    python scripts/build_pdf.py docs/THESIS.md
    python scripts/build_pdf.py docs/THESIS.md --output build/Thesis.pdf
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import markdown
except ImportError:
    sys.exit("The 'markdown' package is required:  pip install markdown")


BROWSER_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]

# A4, serif body text, generous margins - conventional for a submitted thesis.
STYLESHEET = """
@page {
    size: A4;
    margin: 25mm 20mm 22mm 25mm;
}

html {
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
    /* Pin the light scheme: the renderer must not inherit a dark system
       theme, or the printed page comes out with pale text on white. */
    color-scheme: light;
    background: #ffffff;
}

body {
    font-family: Georgia, 'Times New Roman', serif;
    font-size: 10.8pt;
    line-height: 1.55;
    color: #1a1a1a;
    background: #ffffff;
    margin: 0;
    text-align: justify;
    hyphens: auto;
}

/* --- Headings ------------------------------------------------------- */

h1 {
    font-size: 19pt;
    font-weight: 600;
    margin: 0 0 0.8em;
    padding-bottom: 0.25em;
    border-bottom: 2px solid #2c3e50;
    color: #1a2733;
    page-break-after: avoid;
    text-align: left;
}

h2 {
    font-size: 14.5pt;
    font-weight: 600;
    margin: 1.7em 0 0.6em;
    color: #1a2733;
    page-break-after: avoid;
    text-align: left;
}

h3 {
    font-size: 12pt;
    font-weight: 600;
    margin: 1.4em 0 0.5em;
    color: #33475b;
    page-break-after: avoid;
    text-align: left;
}

h1 + p, h2 + p, h3 + p { margin-top: 0; }

/* Chapter openers start on a fresh page. */
h1 { page-break-before: always; }
h1:first-of-type { page-break-before: avoid; }

.pagebreak { page-break-after: always; }

/* --- Body ----------------------------------------------------------- */

p { margin: 0 0 0.75em; orphans: 3; widows: 3; }

ul, ol { margin: 0 0 0.9em; padding-left: 1.5em; }
li { margin-bottom: 0.3em; }

strong { font-weight: 600; color: #111; }

blockquote {
    margin: 1em 0;
    padding: 0.6em 1.1em;
    border-left: 3px solid #b8c4d0;
    background: #f6f8fa;
    font-style: italic;
    color: #3d4852;
    page-break-inside: avoid;
}

/* --- Tables --------------------------------------------------------- */

table {
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0 1.3em;
    font-size: 9.4pt;
    page-break-inside: avoid;
    text-align: left;
}

th {
    background: #2c3e50;
    color: #fff;
    font-weight: 600;
    text-align: left;
    padding: 6px 9px;
    border: 1px solid #2c3e50;
}

td {
    padding: 5px 9px;
    border: 1px solid #cbd5dd;
    vertical-align: top;
    text-align: left;
}

tr:nth-child(even) td { background: #f7f9fb; }

/* --- Code ----------------------------------------------------------- */

code {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 9pt;
    background: #eef1f4;
    padding: 1px 4px;
    border-radius: 3px;
    color: #263238;
}

pre {
    background: #f6f8fa;
    border: 1px solid #d6dee6;
    border-radius: 4px;
    padding: 10px 13px;
    overflow-x: auto;
    font-size: 8.6pt;
    line-height: 1.4;
    page-break-inside: avoid;
    margin: 1em 0;
    text-align: left;
}

pre code { background: none; padding: 0; font-size: inherit; }

/* --- Title block ---------------------------------------------------- */

/* The first heading pair forms the title page. */
body > h1:first-child {
    font-size: 30pt;
    text-align: center;
    border: none;
    margin-top: 22mm;
    margin-bottom: 0.15em;
    letter-spacing: 0.5px;
}

body > h1:first-child + h2 {
    font-size: 15pt;
    font-weight: 400;
    text-align: center;
    color: #33475b;
    margin: 0 0 2.5em;
    font-style: italic;
}

hr { border: none; border-top: 1px solid #cbd5dd; margin: 1.6em 0; }

a { color: #1a4d80; text-decoration: none; }
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>
"""


def find_browser():
    """Return the path to a Chromium-based browser, or None."""
    for candidate in BROWSER_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    for name in ('chrome', 'msedge'):
        found = shutil.which(name)
        if found:
            return found
    return None


def render_html(md_path):
    """Convert a Markdown file to a complete styled HTML document."""
    text = Path(md_path).read_text(encoding='utf-8')
    body = markdown.markdown(
        text,
        extensions=['tables', 'fenced_code', 'attr_list', 'md_in_html', 'sane_lists'],
    )
    title = Path(md_path).stem.replace('-', ' ').replace('_', ' ').title()
    return HTML_TEMPLATE.format(title=title, css=STYLESHEET, body=body)


def build_pdf(md_path, out_path):
    browser = find_browser()
    if not browser:
        sys.exit('No Chrome or Edge installation found; cannot render the PDF.')

    out_path = Path(out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    html = render_html(md_path)

    # Chrome needs a real file on disk; a temporary one keeps the repo clean.
    with tempfile.TemporaryDirectory() as tmp:
        html_file = Path(tmp) / 'document.html'
        html_file.write_text(html, encoding='utf-8')

        profile = Path(tmp) / 'profile'

        result = subprocess.run(
            [
                browser,
                '--headless',
                '--disable-gpu',
                '--no-sandbox',
                '--no-pdf-header-footer',
                f'--user-data-dir={profile}',
                f'--print-to-pdf={out_path}',
                html_file.as_uri(),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

    if not out_path.exists():
        sys.exit(f'PDF was not produced.\n{result.stderr.strip()}')

    size_kb = out_path.stat().st_size / 1024
    print(f'Wrote {out_path}  ({size_kb:.1f} KB)')
    return out_path


def main():
    parser = argparse.ArgumentParser(description='Render Markdown to PDF.')
    parser.add_argument('source', help='path to the Markdown file')
    parser.add_argument('--output', '-o', help='output PDF path')
    args = parser.parse_args()

    source = Path(args.source)
    if not source.exists():
        sys.exit(f'Source file not found: {source}')

    output = args.output or (Path('build') / (source.stem + '.pdf'))
    build_pdf(source, output)


if __name__ == '__main__':
    main()
