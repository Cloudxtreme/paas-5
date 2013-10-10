#!/usr/bin/python

# Copyright (c) 2006-2009 Mitch Garnaat http://garnaat.org/
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, dis-
# tribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the fol-
# lowing conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABIL-
# ITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

setup(name = "cloudbot",
      version = "1.0",
      description = ("cloudbot daemon", "cloudbot core modules" ),
      author = "thomas li",
      author_email = "thomas.li@sinobot.com.cn",
      url = "http://www.sinobot.com.cn",
      packages = [ 
		'cloudbot', 
		'cloudbot.interface',
		"cloudbot.init", 
		'cloudbot.ncSensor', 
		'cloudbot.ccAdaptor', 
		'cloudbot.jiedians',		 
		'cloudbot.gc',
		'cloudbot.clcAPI',
		'cloudbot.ccAPI',
		'cloudbot.walrusAPI',
		'cloudbot.ncAPI',
		'cloudbot.registryAPI',
        'cloudbot.proxyregistryAPI',
        'cloudbot.proxyclcAPI',
	 ],
	 
      package_dir = { '' : '.' }, 

      package_data = {
        'cloudbot' 				: [ '*.py', 'utils/*.py', 'interface/*.py','proxyinterface/*.py' ], 
        'cloudbot.init' 		: [ 'init/*.py' ],
        'cloudbot.ncSensor' 	: [ 'ncSensor/*.py' ],
        'cloudbot.ccAdaptor' 	: [ 'ccAdaptor/*.py' ],
        'cloudbot.jiedians'  	: [ 'jiedians/*py' ],
        'cloudbot.clcAPI'		: [ 'clcAPI/*.py' ],
        'cloudbot.ccAPI'		: [ 'ccAPI/*.py' ],
        'cloudbot.walrusAPI'	: [ 'walrusAPI/*.py' ],
        'cloudbot.ncAPI'		: [ 'ncAPIpy/*.py' ],
        'cloudbot.registryAPI'	: [ 'registryAPI/*.py' ],
        'cloudbot.proxyregistryAPI'	: [ 'proxyregistryAPI/*.py' ],
        'cloudbot.proxyclcAPI'	: [ 'proxyclcAPI/*.py' ],
      },
      license = 'Sinobot',
      platforms = 'Posix;',
      classifiers = [ 'Development Status :: 3 - Alpha',
                      'Intended Audience :: Developers',
                      'License :: OSI Approved :: Sinobot',
                      'Operating System :: OS Independent',
                      'Topic :: Internet',
                      ],
      )
