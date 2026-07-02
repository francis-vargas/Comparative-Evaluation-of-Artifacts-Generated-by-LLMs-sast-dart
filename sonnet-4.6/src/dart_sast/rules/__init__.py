"""Built-in detection rules for dart_sast.

Every module in this package defines exactly one rule class decorated with
``@register_rule``. To add a new rule: create a new module here following
the naming convention ``cweNNN_short_name.py`` and it will be auto-discovered
by ``dart_sast.engine.registry.load_all_rules()``. No other file needs to be
edited.
"""
