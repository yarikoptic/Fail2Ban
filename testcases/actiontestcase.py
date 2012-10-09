# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Author: Cyril Jaquier
# 
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import copy
import unittest, time, os, stat
import tempfile
from server.action import Action


class ExecuteAction(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__action = Action("Test")

	def tearDown(self):
		"""Call after every test case."""
		self.__action.execActionStop()
	
	def testExecuteActionBan(self):
		self.__action.setActionStart("touch /tmp/fail2ban.test")
		self.__action.setActionStop("rm -f /tmp/fail2ban.test")
		self.__action.setActionBan("echo -n")
		self.__action.setActionCheck("[ -e /tmp/fail2ban.test ]")
		
		self.assertTrue(self.__action.execActionBan(None))
		

class PassEnvironment(unittest.TestCase):

	def setUp(self):
		self.__fd, self.__fname = tempfile.mkstemp(prefix='f2b_', text=True)
		self.__ofname = tempfile.mktemp(prefix='f2b_')
		os.write(self.__fd, "#!/bin/sh\nexport >| %s\n" % self.__ofname)   # just report the environment
		os.close(self.__fd)
		os.chmod(self.__fname, stat.S_IXUSR | stat.S_IRUSR)
		
	def tearDown(self):
		os.unlink(self.__fname)
		if os.path.exists(self.__ofname):
			os.unlink(self.__ofname)
			pass


	def _test_exported(self, d):
		"""Check if logfile carried corresponding command but
		environment is clean
		"""
		for k, v in d.iteritems():
			full_key = 'FAIL2BAN_%s' % k
			target = 'export %s="%s"\n' \
			  % (full_key, v.replace('$', r'\$').replace('"', r'\"'))
			self.assertTrue(target in ''.join(open(self.__ofname).readlines()),
				msg="Found no export entry for %s in %s" % (full_key, self.__ofname))
			self.assertFalse(os.getenv(full_key),
							 msg="There should be no %s in environment" % full_key)

	def _assert_no_hit(self, k='FAIL2BAN'):
		file_content = ''.join(open(self.__ofname).readlines())
		self.assertFalse(k in file_content,
			msg="There should have been no %s in %s. Entire content was: %s"
			    % (k, self.__ofname, '\n   ' + file_content.replace('\n', '\n   ')))
	

	def testDoNotPass(self):
		action = Action("TestEnv")		  # must be default
		action.setActionBan(self.__fname)
		action.execActionBan({})
		# There should be no 'FAIL2BAN' in the log file
		self._assert_no_hit()

		# We should not get anything in the file if we pass aInfo or set cInfo
		# or both
		aInfo = {'var1': "LOAD1"}
		action.execActionBan(aInfo)
		self._assert_no_hit()

		action.setCInfo('var2', "LOAD2")
		action.execActionBan({})
		self._assert_no_hit()

		action.execActionBan(aInfo)
		self._assert_no_hit()

	def testPassAInfo(self):
		action = Action("TestEnv", passEnviron=True)
		action.setActionBan(self.__fname)
		action.execActionBan({})
		# There should be no 'FAIL2BAN' in the log file
		self.assertFalse('FAIL2BAN' in ''.join(open(self.__ofname).readlines()))

		# If we pass some variables in aInfo
		aInfo = {'var1': "LOADXX1"}
		action.execActionBan(aInfo)
		self._test_exported(aInfo)

		aInfo['var_long'] = """
		Multiline
		Indented load
		With some $variables etc!
		And some cool symbols inside: {}[]'"?<>~!@#$%^&*()-+
		"""
		action.execActionBan(aInfo)
		self._test_exported(aInfo)

	def testPassCInfo(self):
		action = Action("TestEnv")
		action.setPassEnviron(True)
		action.setActionBan(self.__fname)
		action.execActionBan({})
		# There should be no 'FAIL2BAN' in the log file
		self._assert_no_hit()

		# If we pass some variables in aInfo
		aInfo = {'var1': "LOAD1"}
		cInfo = {'var2': "LOAD2",
				 'var3': "LOAD3"}
		action.execActionBan(aInfo)
		self._test_exported(aInfo)
		self._assert_no_hit('FAIL2BAN_var2')

		for k,v in cInfo.iteritems():
			action.setCInfo(k, v)
		action.execActionBan(aInfo)
		self._test_exported(aInfo)
		self._test_exported(cInfo)
			
