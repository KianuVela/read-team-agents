import os

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    "crapi_site.settings",
)

import django

django.setup()

from django.urls import (
    get_resolver,
    URLPattern,
    URLResolver,
)


HTTP_METHODS = (
    "get",
    "post",
    "put",
    "patch",
    "delete",
)


def get_explicit_methods(callback):
    view_class = (
        getattr(callback, "view_class", None)
        or getattr(callback, "cls", None)
    )

    if view_class is None:
        return []

    return [
        method.upper()
        for method in HTTP_METHODS
        if method in view_class.__dict__
    ]


def walk(patterns, prefix=""):

    for pattern in patterns:

        current = prefix + str(pattern.pattern)

        if isinstance(pattern, URLResolver):

            walk(
                pattern.url_patterns,
                current,
            )

        elif isinstance(pattern, URLPattern):

            if not current.startswith("workshop/api/"):
                continue

            methods = get_explicit_methods(
                pattern.callback
            )

            view_class = (
                getattr(
                    pattern.callback,
                    "view_class",
                    None,
                )
                or getattr(
                    pattern.callback,
                    "cls",
                    None,
                )
            )

            view_name = (
                view_class.__name__
                if view_class
                else str(pattern.callback)
            )

            print(
                "|".join(
                    [
                        ",".join(methods),
                        current,
                        view_name,
                    ]
                )
            )


walk(
    get_resolver().url_patterns
)