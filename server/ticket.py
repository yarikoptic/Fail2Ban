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

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

class Ticket:
	
	def __init__(self, ip, time, matches=None):
		"""Ticket constructor

		@param ip the IP address
		@param time the ban time
		@param matches (log) lines caused the ticket
		"""

		self.setIP(ip)
		self._time = time
		self._failures = 0
		self._matches = matches or []

	def __str__(self):
		return "%s: ip=%s time=%s #attempts=%d" % \
			   (self.__class__.__name__.split('.')[-1],
				self._ip, self._time, self._failures)

	def __getitem__(self, k):
		"""Convenience to mimic a dict behavior

		so it could serve previously used aInfo (i.e. for strings interpolations etc)
		"""
		if k == 'matches':
			return "".join(self._matches)
		else:
			return getattr(self, '_' + k)

	def iteritems(self):
		for k in ('ip', 'failures', 'matches', 'time'):
			yield (k, self[k])

	def setIP(self, value):
		if isinstance(value, basestring):
			# guarantee using regular str instead of unicode for the IP
			value = str(value)
		self._ip = value
	
	def getIP(self):
		return self._ip

	def setTime(self, value):
		self._time = value
	
	def getTime(self):
		return self._time
	
	def setFailures(self, value):
		self._failures = value
	
	def getFailures(self):
		return self._failures

	def getMatches(self):
		return self._matches


class FailTicket(Ticket):
	pass


##
# Ban Ticket.
#
# This class extends the Ticket class. It is mainly used by the BanManager.

class BanTicket(Ticket):
	pass
