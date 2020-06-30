import time
import sys

from twisted.conch.ssh.userauth import SSHUserAuthServer
import struct
from twisted.conch import error, interfaces
from twisted.conch.ssh import keys, transport, service
from twisted.conch.ssh.common import NS, getNS
from twisted.cred import credentials
from twisted.cred.error import UnauthorizedLogin
from twisted.internet import defer, reactor
from twisted.python import failure, log

from twisted.conch.ssh.transport import SSHCiphers

from models import *
from general import insertSysLog
import datetime


class MiladSSHAuthServer(SSHUserAuthServer):
    """
    A service implementing the server side of the 'ssh-userauth' service.  It
    is used to authenticate the user on the other side as being able to access
    this server.

    @ivar name: the name of this service: 'ssh-userauth'
    @type name: C{str}
    @ivar authenticatedWith: a list of authentication methods that have
        already been used.
    @type authenticatedWith: C{list}
    @ivar loginTimeout: the number of seconds we wait before disconnecting
        the user for taking too long to authenticate
    @type loginTimeout: C{int}
    @ivar attemptsBeforeDisconnect: the number of failed login attempts we
        allow before disconnecting.
    @type attemptsBeforeDisconnect: C{int}
    @ivar loginAttempts: the number of login attempts that have been made
    @type loginAttempts: C{int}
    @ivar passwordDelay: the number of seconds to delay when the user gives
        an incorrect password
    @type passwordDelay: C{int}
    @ivar interfaceToMethod: a C{dict} mapping credential interfaces to
        authentication methods.  The server checks to see which of the
        cred interfaces have checkers and tells the client that those methods
        are valid for authentication.
    @type interfaceToMethod: C{dict}
    @ivar supportedAuthentications: A list of the supported authentication
        methods.
    @type supportedAuthentications: C{list} of C{str}
    @ivar user: the last username the client tried to authenticate with
    @type user: C{str}
    @ivar method: the current authentication method
    @type method: C{str}
    @ivar nextService: the service the user wants started after authentication
        has been completed.
    @type nextService: C{str}
    @ivar portal: the L{twisted.cred.portal.Portal} we are using for
        authentication
    @type portal: L{twisted.cred.portal.Portal}
    @ivar clock: an object with a callLater method.  Stubbed out for testing.
    """
    name = 'ssh-userauth'
    attacker = None
    loginTimeout = 10 * 60 * 60
    # 10 minutes before we disconnect them
    attemptsBeforeDisconnect = 3
    # 20 login attempts before a disconnect
    passwordDelay = 1 # number of seconds to delay on a failed password
    clock = reactor
    interfaceToMethod = {
        credentials.ISSHPrivateKey : 'publickey',
        credentials.IUsernamePassword : 'password',
    }


    def serviceStarted(self):
        """
        Called when the userauth service is started.  Set up instance
        variables, check if we should allow password authentication (only
        allow if the outgoing connection is encrypted) and set up a login
        timeout.
        """
        self.authenticatedWith = []
        self.loginAttempts = 0
        self.user = None
        self.nextService = None
        self.portal = self.transport.factory.portal

        self.supportedAuthentications = []
        for i in self.portal.listCredentialsInterfaces():
            if i in self.interfaceToMethod:
                self.supportedAuthentications.append(self.interfaceToMethod[i])

        if not self.transport.isEncrypted('in'):
            # don't let us transport password in plaintext
            if 'password' in self.supportedAuthentications:
                self.supportedAuthentications.remove('password')
        self._cancelLoginTimeout = self.clock.callLater(
            self.loginTimeout,
            self.timeoutAuthentication)

    def serviceStopped(self):
        """
        Called when the userauth service is stopped.  Cancel the login timeout
        if it's still going.
        """
        if self._cancelLoginTimeout:
            self._cancelLoginTimeout.cancel()
            self._cancelLoginTimeout = None


    def timeoutAuthentication(self):
        """
        Called when the user has timed out on authentication.  Disconnect
        with a DISCONNECT_NO_MORE_AUTH_METHODS_MiladILABLE message.
        """
        self._cancelLoginTimeout = None
        self.transport.sendDisconnect(
            transport.DISCONNECT_NO_MORE_AUTH_METHODS_MiladILABLE,
            'you took too long')


    def tryAuth(self, kind, user, data):
        """
        Try to authenticate the user with the given method.  Dispatches to a
        auth_* method.

        @param kind: the authentication method to try.
        @type kind: C{str}
        @param user: the username the client is authenticating with.
        @type user: C{str}
        @param data: authentication specific data sent by the client.
        @type data: C{str}
        @return: A Deferred called back if the method succeeded, or erred back
            if it failed.
        @rtype: C{defer.Deferred}
        """
        log.msg('%s trying auth %s' % (user, kind))
        if kind not in self.supportedAuthentications:
            return defer.fail(
                    error.ConchError('unsupported authentication, failing'))
        kind = kind.replace('-', '_')
        f = getattr(self,'auth_%s'%kind, None)
        if f:
            ret = f(data)
            if not ret:
                return defer.fail(
                        error.ConchError('%s return None instead of a Deferred'
                            % kind))
            else:
                return ret
        return defer.fail(error.ConchError('bad auth type: %s' % kind))


    def ssh_USERAUTH_REQUEST(self, packet):
        """
        The client has requested authentication.  Payload::
            string user
            string next service
            string method
            <authentication specific data>

        @type packet: C{str}
        """
        user, nextService, method, rest = getNS(packet, 3)
        # print method
        if user != self.user or nextService != self.nextService:
            self.authenticatedWith = [] # clear auth state
        self.user = user
        self.nextService = nextService
        self.method = method
        d = self.tryAuth(method, user, rest)
        if not d:
            self._ebBadAuth(
                failure.Failure(error.ConchError('auth returned none')))
            return
        d.addCallback(self._cbFinishedAuth)
        d.addErrback(self._ebMaybeBadAuth)
        d.addErrback(self._ebBadAuth)
        return d


    def _cbFinishedAuth(self, (interface, Miladtar, logout)):
        """
        The callback when user has successfully been authenticated.  For a
        description of the arguments, see L{twisted.cred.portal.Portal.login}.
        We start the service requested by the user.
        """
        self.transport.Miladtar = Miladtar
        self.transport.logoutFunction = logout
        service = self.transport.factory.getService(self.transport,
                self.nextService)
        if not service:
            raise error.ConchError('could not get next service: %s'
                                  % self.nextService)
        log.msg('%s authenticated with %s' % (self.user, self.method))
        ##############################################################################
        self.transport.sendPacket(MSG_USERAUTH_SUCCESS, '')
        self.transport.setService(service())


    def _ebMaybeBadAuth(self, reason):
        """
        An intermediate errback.  If the reason is
        error.NotEnoughAuthentication, we send a MSG_USERAUTH_FAILURE, but
        with the partial success indicator set.

        @type reason: L{twisted.python.failure.Failure}
        """
        reason.trap(error.NotEnoughAuthentication)
        self.transport.sendPacket(MSG_USERAUTH_FAILURE,
                NS(','.join(self.supportedAuthentications)) + '\xff')


    def _ebBadAuth(self, reason):
        """
        The final errback in the authentication chain.  If the reason is
        error.IgnoreAuthentication, we simply return; the authentication
        method has sent its own response.  Otherwise, send a failure message
        and (if the method is not 'none') increment the number of login
        attempts.

        @type reason: L{twisted.python.failure.Failure}
        """
        if reason.check(error.IgnoreAuthentication):
            return
        if self.method != 'none':
            log.msg('%s failed auth %s' % (self.user, self.method))
            if reason.check(UnauthorizedLogin):
                log.msg('unauthorized login: %s' % reason.getErrorMessage())
            elif reason.check(error.ConchError):
                log.msg('reason: %s' % reason.getErrorMessage())
            else:
                log.msg(reason.getTraceback())
            self.loginAttempts += 1
            if self.loginAttempts > self.attemptsBeforeDisconnect:
                self.transport.sendDisconnect(
                        transport.DISCONNECT_NO_MORE_AUTH_METHODS_MiladILABLE,
                        'too many bad auths')
                return
        self.transport.sendPacket(
                MSG_USERAUTH_FAILURE,
                NS(','.join(self.supportedAuthentications)) + '\x00')


    def auth_publickey(self, packet):
        """
        Public key authentication.  Payload::
            byte has signature
            string algorithm name
            string key blob
            [string signature] (if has signature is True)

        Create a SSHPublicKey credential and verify it using our portal.
        """
        hasSig = ord(packet[0])
        algName, blob, rest = getNS(packet[1:], 2)
        pubKey = keys.Key.fromString(blob)
        signature = hasSig and getNS(rest)[0] or None
        if hasSig:
            b = (NS(self.transport.sessionID) + chr(MSG_USERAUTH_REQUEST) +
                NS(self.user) + NS(self.nextService) + NS('publickey') +
                chr(hasSig) +  NS(pubKey.sshType()) + NS(blob))
            c = credentials.SSHPrivateKey(self.user, algName, blob, b,
                    signature)
            return self.portal.login(c, None, interfaces.IConchUser)
        else:
            c = credentials.SSHPrivateKey(self.user, algName, blob, None, None)
            return self.portal.login(c, None,
                    interfaces.IConchUser).addErrback(self._ebCheckKey,
                            packet[1:])


    def _ebCheckKey(self, reason, packet):
        """
        Called back if the user did not sent a signature.  If reason is
        error.ValidPublicKey then this key is valid for the user to
        authenticate with.  Send MSG_USERAUTH_PK_OK.
        """
        reason.trap(error.ValidPublicKey)
        # if we make it here, it means that the publickey is valid
        self.transport.sendPacket(MSG_USERAUTH_PK_OK, packet)
        return failure.Failure(error.IgnoreAuthentication())


    def auth_password(self, packet):
        """
        Password authentication.  Payload::
            string password

        Make a UsernamePassword credential and verify it with our portal.
        """
        password = getNS(packet[1:])[0]
        c = credentials.UsernamePassword(self.user, password)
        reactor.callFromThread(self.prepare_to_save, password)
        return self.portal.login(c, None, interfaces.IConchUser).addErrback(
                                                        self._ebPassword)


    def _ebPassword(self, f):
        """
        If the password is invalid, wait before sending the failure in order
        to delay brute-force password guessing.
        """
        d = defer.Deferred()
        self.clock.callLater(self.passwordDelay, d.callback, f)
        return d


    def prepare_to_save(self, password):
        """
        If self.attacker is not None it will add /1/ to auth_count and save it,
        also add record for this attacker to SSHAttackerAuth.
        Else it will search in database if there's any attacker with this IP. (set_attacker)
        """
        if self.attacker:
            self.attacker.save().addCallback(self.add_auth_record, password)
        else:
            SSHAttacker.find(
                where=['ip = ?', self.transport.transport.getPeer().host], limit=1
                ).addCallback(self.set_attacker, password)

    def set_attacker(self, attacker, password):
        """
        If it could find attacker with the IP it will set it as self.attacker,
        Else it will Make New record in SSHAttacker table and set it as self.attacker.
        """
        if attacker:
            self.attacker = attacker
        else:
            self.attacker = SSHAttacker()
            self.attacker.connection_count = 0
            self.attacker.connection_count_30 = 0
            self.attacker.connection_count_90 = 0
            self.attacker.connection_count_year = 0
            self.attacker.connection_count_all = 0
            
            self.attacker.auth_count_30 = 0
            self.attacker.auth_count_90 = 0
            self.attacker.auth_count_year = 0
            self.attacker.auth_count_all = 0

            self.attacker.success_auth_count_30 = 0
            self.attacker.success_auth_count_90 = 0
            self.attacker.success_auth_count_year = 0
            self.attacker.success_auth_count_all = 0

            self.attacker.command_count_30 = 0
            self.attacker.command_count_90 = 0
            self.attacker.command_count_year = 0
            self.attacker.command_count_all = 0

            self.attacker.success_command_count_30 = 0
            self.attacker.success_command_count_90 = 0
            self.attacker.success_command_count_year = 0
            self.attacker.success_command_count_all = 0
            self.attacker.last_activity = time.time()
            self.attacker.ip = self.transport.transport.getPeer().host
        self.attacker.save().addCallback(self.add_auth_record, password)

    def add_auth_record(self, attacker, password):
        """
        """
        SSHFakeUser.find(
            where=['username = ?', self.user], limit=1
            ).addCallback(self.add_auth_record_continue, attacker, password)

    def add_auth_record_continue(self, user, attacker, password):
        """
        """
        attacked_time = time.time()
        auth = SSHAttackerAuth()
        auth.attacker_id = self.attacker.id
        auth.username = self.user
        auth.password = password
        if user and user.password == password:
            auth.status = True
        else:
            auth.status = False
        auth.timestamp = attacked_time
        auth.save()
        syslog_msg ='date={date} time={time} MiladPotProtocol={MiladPotProtocol} ip={ip} type_cmd={type_cmd} username={username}'\
                'password={password}  status={status} command={command}\n'\
            .format(date=datetime.datetime.fromtimestamp(attacked_time).strftime('%Y-%m-%d'),
                    time=datetime.datetime.fromtimestamp(attacked_time).strftime('%H:%M:%S'),
                    MiladPotProtocol='ssh',
                    ip=self.transport.transport.getPeer().host,
                    type_cmd="auth",
                    username=self.user,
                    password=password,
                    status='',
                    command=''
                    )
        insertSysLog(syslog_msg)



MSG_USERAUTH_REQUEST          = 50
MSG_USERAUTH_FAILURE          = 51
MSG_USERAUTH_SUCCESS          = 52
MSG_USERAUTH_BANNER           = 53
MSG_USERAUTH_INFO_RESPONSE    = 61
MSG_USERAUTH_PK_OK            = 60

messages = {}
for k, v in locals().items():
    if k[:4]=='MSG_':
        messages[v] = k

SSHUserAuthServer.protocolMessages = messages
del messages
del v

# Doubles, not included in the protocols' mappings
MSG_USERAUTH_PASSWD_CHANGEREQ = 60
MSG_USERAUTH_INFO_REQUEST     = 60