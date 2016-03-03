import os.path

for settings_name in ("default_settings.py", "settings.py"):
    settings_path = os.path.join(os.path.dirname(__file__), settings_name)
    if os.path.exists(settings_path):
        execfile(settings_path, globals(), locals())
