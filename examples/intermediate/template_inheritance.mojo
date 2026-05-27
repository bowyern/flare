"""Example: template inheritance via ``{% block %}`` + ``{% extends %}``.

Two compiled templates, one parent + one child, rendered through
``Template.render_extending`` so the child's blocks slot into the
parent's surrounding HTML.

Pure construction -- no live network. Demonstrates the v0.8 Track J
addition to ``flare.http.template``.

Run:
    pixi run example-template-inheritance
"""

from flare.http.template import Template, TemplateContext


def main() raises:
    print("=== flare: template inheritance ===")
    print()

    var parent = Template.compile(
        String(
            "<!doctype html>"
            "<html><head><title>"
            "{% block title %}flare app{% endblock %}"
            "</title></head>"
            "<body>"
            "<header>{% block header %}default header{% endblock %}</header>"
            "<main>{% block content %}default content{% endblock %}</main>"
            "<footer>flare</footer>"
            "</body></html>"
        )
    )

    # Child template: overrides title + content, leaves header as default.
    var child = Template.compile(
        String(
            '{% extends "layout.html" %}'
            "{% block title %}{{ page_title }}{% endblock %}"
            "{% block content %}<p>Hello {{ user }}!</p>{% endblock %}"
        )
    )

    print("child.extends_target =", child.extends_target)
    print("child.blocks defines:", len(child.blocks), "named regions")
    print()

    var ctx = TemplateContext()
    ctx.set(String("page_title"), String("Welcome"))
    ctx.set(String("user"), String("Ada"))

    var html = child.render_extending(ctx, parent)
    print("rendered:")
    print(html)
    print()
    print(
        "note: header used parent default; title + content used child"
        " overrides."
    )
