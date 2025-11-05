# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import suricata_check

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "suricata-check"
copyright = "2024, Koen Teuwen"
author = "Koen Teuwen"

# Version / release information
version = suricata_check.__version__
release = suricata_check.__version__

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "myst_parser",
    "autoapi.extension",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx_click",
    "sphinx_sitemap",
]

templates_path = ["_templates"]
source_suffix = [".rst", ".md"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master", None),
}

root_doc = "index"
master_doc = "index"

suppress_warnings = []

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "prev_next_buttons_location": "both",
    "style_external_links": True,
}
html_static_path = ["static"]
html_favicon = "https://docs.readthedocs.io/favicon.ico"

html_js_files = ["js/script.js"]

# -- Options for MyST     -------------------------------------------------
# https://myst-parser.readthedocs.io/en/latest/

myst_enable_extensions = ["linkify"]
myst_heading_anchors = 5

autoapi_dirs = ["../suricata_check"]
autoapi_options = [
    "members",
    "show-inheritance",
    "show-module-summary",
    "special-members",
    "imported-members",
]
autoapi_add_toctree_entry = False
autoapi_python_class_content = "both"
autoapi_member_order = "groupwise"
autoapi_own_page_level = "module"

# -- Options for viewcode     -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/viewcode.html

viewcode_line_numbers = True

# -- Options for sphinx-sitemap    -------------------------------------------------
# https://sphinx-sitemap.readthedocs.io/en/latest/index.html

html_baseurl = "https://suricata-check.teuwen.net/"
sitemap_url_scheme = "{link}"
sitemap_locales = ["en"]
sitemap_excludes = ["search.html", "genindex.html"]
html_extra_path = ["robots.txt"]
