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
    "sphinx.ext.autodoc",
    "autoapi.extension",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx_click",
]

templates_path = ["_templates"]
source_suffix = [".rst", ".md"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master", None),
    "idstools": ("https://idstools.readthedocs.io/en/latest/", None),
    "numpy": ("https://numpy.org/doc/stable", None),
    "sklearn": ("https://scikit-learn.org/stable", None),
    "pandas": ("https://pandas.pydata.org/docs", None),
    "xgboost": ("https://xgboost.readthedocs.io/en/stable/", None),
}

root_doc = "index"
master_doc = "index"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["static"]

# -- Options for MyST     -------------------------------------------------
# https://myst-parser.readthedocs.io/en/latest/

myst_enable_extensions = ["linkify"]
myst_heading_anchors = 5

# -- Options for Autodoc     -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html#configuration

autoclass_context = "both"
autodoc_class_signature = "separated"
autodoc_member_order = "groupwise"
autodoc_default_flags = [
    "members",
    "special-members",
    "inherited-members",
    "show-inheritance",
    "ignore-module-all",
    "maxdepth",
]
autodoc_default_options = {
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": False,
    "maxdepth": 2,
}
autodoc_typehints = "both"
autodoc_typehints_description_target = "all"

# -- Options for AutoAPI     -------------------------------------------------
# https://sphinx-autoapi.readthedocs.io/en/latest/

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