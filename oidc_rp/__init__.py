__version__ = '0.3.3'

# Deploying a new version:
# 1. remove the ".dev" from the current version number
# 2. create a new commit (eg. "Prepared 0.1.1 release")
# 3. run "git tag x.y.z" (eg. "git tag 0.1.1")
# 4. run "python setup.py sdist bdist_wheel upload"
# 5. bump the version (increment the version and append a ".dev" to it). eg. "0.1.2.dev"
# 6. create a new commit (eg. "Bumped version to 0.1.2.dev")
# 7. run "git push" and "git push --tags"


default_app_config = 'oidc_rp.apps.OIDCRelyingPartyAppConfig'
