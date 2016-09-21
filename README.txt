.. image:: https://img.shields.io/codeship/e37b1c90-6212-0134-3d52-0627957cda96/default.svg
   :target: https://bitbucket.org/hellwig/cenvars-client
.. image:: https://coveralls.io/repos/bitbucket/hellwig/cenvars-client/badge.svg?branch=default 
   :target: https://coveralls.io/bitbucket/hellwig/cenvars-client?branch=default
.. image:: https://img.shields.io/pypi/v/cenvars-client.svg
   :target: https://pypi.python.org/pypi/cenvars-client/
.. image:: https://img.shields.io/badge/Donate-PayPal-blue.svg
   :target: https://paypal.me/MartinHellwig
.. image:: https://img.shields.io/badge/Donate-Patreon-orange.svg
   :target: https://www.patreon.com/hellwig
   

##############
Cenvars Client
##############

What is it?
===========
A client library and scripts for cenvars.

What problem does it solve?
===========================
This fetches from a cenvars server environment variables

How do I install it?
====================
pip install cenvars-client

How do I use it?
================

Library
-------
.. sourcecode:: shell

  from cenvars import api


Library
-------
.. sourcecode:: python

  $ cenvars_newkey -s "https://cenvarsserver.example.com/cenvars/
  $ # This will return an encoded cenvars_key, however in normal operation this
  $ # will be provided by the cenvar server. For now we assume that the key is
  $ # stored in the environment under the key CENVARS_KEY
  $
  $ source <(cenvars)
  $ # This will contact the cenvars server, fetch the environment variables and
  $ # add it to the current shell session.

What license is this?
=====================
Two-clause BSD


How can I get support?
======================
Please use the repo's bug tracker to leave behind any questions, feedback,
suggestions and comments. I will handle them depending on my time and what looks
interesting. If you require guaranteed support please contact me via
e-mail so we can discuss appropriate compensation.


Signing Off
===========
Is my work helpful or valuable to you? You can repay me by donating via:

https://paypal.me/MartinHellwig

.. image:: https://img.shields.io/badge/PayPal-MartinHellwig-blue.svg
  :target: https://paypal.me/MartinHellwig
  :alt: Donate via PayPal.Me
  :scale: 120 %

-or-

https://www.patreon.com/hellwig

.. image:: https://img.shields.io/badge/Patreon-hellwig-orange.svg
  :target: https://www.patreon.com/hellwig
  :alt: Donate via Patreon
  :scale: 120 %


Thank you!