#!/usr/bin/env python3
"""
Markdown to PDF converter using markdown and weasyprint
"""

import markdown
from weasyprint import HTML, CSS
import sys
import os

def convert_md_to_pdf(md_file, pdf_file):
    """
    Convert Markdown file to PDF

    Args:
        md_file: Path to input Markdown file
        pdf_file: Path to output PDF file
    """
    print(f"Reading Markdown file: {md_file}")

    # Read Markdown file
    with open(md_file, 'r', encoding='utf-8') as f:
        md_content = f.read()

    print("Converting Markdown to HTML...")

    # Convert Markdown to HTML with extensions
    html_content = markdown.markdown(
        md_content,
        extensions=[
            'markdown.extensions.tables',      # Table support
            'markdown.extensions.fenced_code',  # Code blocks
            'markdown.extensions.codehilite',   # Syntax highlighting
            'markdown.extensions.toc',          # Table of contents
        ]
    )

    # Add CSS styling for better PDF output
    css_style = """
    <style>
        @page {
            size: A4;
            margin: 2cm;
        }
        body {
            font-family: 'Helvetica', 'Arial', 'Noto Sans CJK JP', 'Yu Gothic', 'Meiryo', sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #333;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            page-break-before: always;
        }
        h1:first-of-type {
            page-break-before: avoid;
        }
        h2 {
            color: #2980b9;
            border-bottom: 2px solid #bdc3c7;
            padding-bottom: 5px;
            margin-top: 30px;
        }
        h3 {
            color: #16a085;
            margin-top: 20px;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 10pt;
        }
        pre {
            background-color: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            font-size: 9pt;
        }
        pre code {
            background-color: transparent;
            padding: 0;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            font-size: 10pt;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px 12px;
            text-align: left;
        }
        th {
            background-color: #3498db;
            color: white;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        blockquote {
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-left: 0;
            color: #555;
            font-style: italic;
        }
        strong {
            color: #e74c3c;
        }
        a {
            color: #3498db;
            text-decoration: none;
        }
        hr {
            border: none;
            border-top: 2px solid #ecf0f1;
            margin: 30px 0;
        }
        .page-break {
            page-break-after: always;
        }
    </style>
    """

    # Combine HTML with CSS
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>ネットワーク入門</title>
        {css_style}
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """

    print("Generating PDF...")

    # Convert HTML to PDF
    HTML(string=full_html).write_pdf(pdf_file)

    print(f"PDF generated successfully: {pdf_file}")

if __name__ == "__main__":
    md_file = "/home/user/LocalNetScan/network_introduction.md"
    pdf_file = "/home/user/LocalNetScan/network_introduction.pdf"

    if not os.path.exists(md_file):
        print(f"Error: Markdown file not found: {md_file}")
        sys.exit(1)

    try:
        convert_md_to_pdf(md_file, pdf_file)
        print("\n✅ Conversion completed successfully!")
        print(f"   Input:  {md_file}")
        print(f"   Output: {pdf_file}")
    except Exception as e:
        print(f"\n❌ Error during conversion: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
