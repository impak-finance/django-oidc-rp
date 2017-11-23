How to run the example project?
===============================

.. code-block:: shell

    $ pipenv install --dev
    $ cp example_project/settings/settings_env.py.example example_project/settings/settings_env.py
    # Edit example_project/settings/settings_env.py with the configuration related to the client app
    # created at the OpenID Connect Provider (OP) level.
    $ make migrate
    $ make devserver
