# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :
"""Fail2Ban -- ban hosts that cause multiple authentication failures.

This module is primarily for use by fail2ban-* command line tools.

License
-------

Fail2Ban is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Fail2Ban is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Fail2Ban; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""

__copyright__ = "Copyright (c) 2004-2012 Fail2Ban developers"
__license__ = "GPL"

from fail2ban.common.version import version as __version__
