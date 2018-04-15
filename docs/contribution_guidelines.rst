#######################
Contribution guidelines
#######################

Here are some simple rules & tips to help you contribute to django-oidc-rp. You can contribute in
many ways!

Contributing code
=================

The preferred way to contribute to django-oidc-rp is to submit pull requests to the
`project's Github repository <https://github.com/impak-finance/django-oidc-rp>`_. Here are some
general tips regarding pull requests.

Development environment
-----------------------

.. note::

    The following steps assumes you have `Pipenv <https://docs.pipenv.org/>`_ installed on your
    system.

You should first fork the
`django-oidc-rp's repository <https://github.com/impak-finance/django-oidc-rp>`_. Then you can get a
working copy of the project using the following commands:

.. code-block:: bash

    $ git clone git@github.com:<username>/django-oidc-rp.git
    $ cd django-oidc-rp
    $ make

Coding style
~~~~~~~~~~~~

Please make sure that your code is compliant with the
`PEP8 style guide <https://www.python.org/dev/peps/pep-0008/>`_. You can ignore the "Maximum Line
Length" requirement but the length of your lines should not exceed 100 characters. Remember that
your code will be checked using `flake8 <https://pypi.org/project/flake8/>`_ and
`isort <https://pypi.org/project/isort/>`_. You can use the following command to trigger such
quality assurance checks:

.. code-block:: bash

    $ make qa

Tests
~~~~~

You should not submit pull requests without providing tests. Django-oidc-rp relies on
`pytest <http://pytest.org/latest/>`_: py.test is used instead of unittest for its test runner but
also for its syntax. So you should write your tests using `pytest <http://pytest.org/latest/>`_
instead of unittest and you should not use the standard ``TestCase``.

You can run the whole test suite using the following command:

.. code-block:: bash

    $ make tests

Code coverage should not decrease with pull requests! You can easily get the code coverage of the
project using the following command:

.. code-block:: bash

    $ make coverage


Using the issue tracker
=======================

You should use the
`project's issue tracker <https://github.com/impak-finance/django-oidc-rp/issues>`_ if you've found
a bug or if you want to propose a new feature. Don't forget to include as many details as possible
in your tickets (eg. tracebacks if this is appropriate).

Security
========

If you've found a security issue please **do not open a Github issue**. Instead, send an email at
``tech@impakfinance.com``. We'll then investigate together to resolve the problem so we can make
an announcement about a solution along with the vulnerability.
