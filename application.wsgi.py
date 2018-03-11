#!/usr/bin/python
import sys, os
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))))

from application import app as application
application.secret_key = 'super_secret_key'
