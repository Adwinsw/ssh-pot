from __future__ import division, absolute_import

import os

from zope.interface import implementer, Interface, Attribute

from twisted.logger import Logger
from twisted.internet import defer
from twisted.python import failure
from twisted.cred import error, credentials, checkers

from ssh.models import SSHFakeUser

@implementer(checkers.ICredentialsChecker)
class InDataBaseChecker(object):
    credentialInterfaces = (credentials.IUsernamePassword,
                            credentials.IUsernameHashedPassword)

    def _cbPasswordMatch(self, matched, username):
        if matched:
            return username
        else:
            return failure.Failure(error.UnauthorizedLogin())

    def requestMiladtarId(self, credentials):
        return SSHFakeUser.find(
            where=['username = ?', credentials.username], limit=1
            ).addCallback(self.continue_requestMiladtarId, credentials)

    def continue_requestMiladtarId(self, user, credentials):
        if user:
            return defer.maybeDeferred(
                credentials.checkPassword,
                user.password).addCallback(
                self._cbPasswordMatch, bytes(credentials.username))            
        else:
            return defer.fail(error.UnauthorizedLogin())

