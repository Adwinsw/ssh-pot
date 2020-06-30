import time
import struct
# 3rd Party Libraries
from twisted.internet import reactor, protocol
from twisted.protocols.policies import TimeoutMixin
from twisted.cred import portal
from twisted.conch.ssh import factory, connection, keys, session, transport
from zope.interface import implements
from twisted.conch import avatar, recvline
from twisted.conch.ssh.transport import SSHCiphers
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.insults import insults
from twisted.cred import checkers

from twisted.conch.ssh import address, _kex, keys
from twisted.python import log, randbytes
from twisted.conch.ssh.common import NS, getNS, MP, getMP, _MPpow, ffs
# In Project things
from consts import ssh_versions
from userauth import AvaSSHAuthServer
from checker import InDataBaseChecker
from ssh.models import *
from general import insertSysLog
import datetime


MISSING_OPERAND = '''mkdir: missing operand
Try 'mkdir --help' for more information.\n'''
MISSING_ARGUMENT = '''mkdir: option requires an argument -- 'm'
Try 'mkdir --help' for more information.\n'''
VERSION_INFO = '''mkdir (GNU coreutils) 8.22
Copyright (C) 2013 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by David MacKenzie.
\n'''
HELP_INFO = '''Usage: mkdir [OPTION]... DIRECTORY...
Create the DIRECTORY(ies), if they do not already exist.

Mandatory arguments to long options are mandatory for short options too.
  -m, --mode=MODE   set file mode (as in chmod), not a=rwx - umask
  -p, --parents     no error if existing, make parent directories as needed
  -v, --verbose     print a message for each created directory
  -Z                   set SELinux security context of each created directory
                         to the default type
      --context[=CTX]  like -Z, or if CTX is specified then set the SELinux
                         or SMACK security context to CTX
      --help     display this help and exit
      --version  output version information and exit

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
For complete documentation, run: info coreutils 'mkdir invocation'
\n'''

class AvaSSHServerTransport(transport.SSHServerTransport, TimeoutMixin):

    version = 'OpenSSH_6.6.1p1'
    protocolVersion = "2.0"
    comment = 'Ubuntu-2ubuntu2.3'
    timeout = 180

    ourVersionString = ('SSH-' + protocolVersion + '-' + version + ' '
            + comment).strip()

    def connectionMade(self):
        """
        Called when the connection is made to the other side.  We sent our
        version and the MSG_KEXINIT packet.
        """
        self.transport.write('%s\r\n' % (self.ourVersionString,))
        self.currentEncryptions = SSHCiphers('none', 'none', 'none', 'none')
        self.currentEncryptions.setKeys('', '', '', '', '', '')
        self.sendKexInit()
        self.setTimeout(self.timeout)
    #     SSHAttacker.find(
    #         where=['ip = ?', self.transport.getPeer().host], limit=1
    #         ).addCallback(self.set_attacker)

    # def set_attacker(self, attacker):
    #     """
    #     If it could find attacker with the IP it will set it as self.attacker,
    #     Else it will Make New record in SSHAttacker table and set it as self.attacker.
    #     """
    #     if attacker:
    #         self.attacker = attacker
    #         self.save_connection()
    #     else:
    #         self.attacker = SSHAttacker()
    #         self.attacker.ip = self.transport.getPeer().host
    #         self.attacker.connection_count = 1
    #         self.attacker.auth_count = 0
    #         self.attacker.success_auth_count = 0
    #         self.attacker.command_count = 0
    #         self.attacker.success_command_count = 0
    #         self.attacker.last_activity = time.time()
    #         self.attacker.save().addCallback(self.save_connection)

    # def save_connection(self):
    #     self.attacker.connection_count += 1
    #     self.attacker.save()
    #     connection = SSHConnection()
    #     connection.attacker_id = self.attacker.id
    #     connection.timestamp = time.time()
    #     connection.save()

    def dataReceived(self, data):
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        self.buf = self.buf + data
        if not self.gotVersion:
            if self.buf.find('\n', self.buf.find('SSH-')) == -1:
                return
            lines = self.buf.split('\n')
            for p in lines:
                if p.startswith('SSH-'):
                    self.gotVersion = True
                    self.otherVersionString = p.strip()
                    remoteVersion = p.split('-')[1]
                    if remoteVersion not in self.supportedVersions:
                        self._unsupportedVersionReceived(remoteVersion)
                        return
                    i = lines.index(p)
                    self.buf = '\n'.join(lines[i + 1:])
        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()

    def dispatchMessage(self, messageNum, payload):
        """
        Send a received message to the appropriate method.

        @type messageNum: C{int}
        @type payload: c{str}
        """
        messages = transport.messages
        if messageNum < 50 and messageNum in messages:
            messageType = messages[messageNum][4:]
            f = getattr(self, 'ssh_%s' % messageType, None)
            if f is not None:
                f(payload)
            else:
                log.msg("couldn't handle %s" % messageType)
                log.msg(repr(payload))
                self.sendUnimplemented()
        elif self.service:
            log.callWithLogger(self.service, self.service.packetReceived,
                               messageNum, payload)
        else:
            log.msg("couldn't handle %s" % messageNum)
            log.msg(repr(payload))
            self.sendUnimplemented()

publicKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAGEArzJx8OYOnJmzf4tfBEvLi8DVPrJ3/c9k2I/Az64fxjHf9imyRJbixtQhlH9lfNjUIx+4LmrJH5QNRsFporcHDKOTwTTYLh5KmRpslkYHRivcJSkbh/C+BR3utDS555mV'

privateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIByAIBAAJhAK8ycfDmDpyZs3+LXwRLy4vA1T6yd/3PZNiPwM+uH8Yx3/YpskSW
4sbUIZR/ZXzY1CMfuC5qyR+UDUbBaaK3Bwyjk8E02C4eSpkabJZGB0Yr3CUpG4fw
vgUd7rQ0ueeZlQIBIwJgbh+1VZfr7WftK5lu7MHtqE1S1vPWZQYE3+VUn8yJADyb
Z4fsZaCrzW9lkIqXkE3GIY+ojdhZhkO1gbG0118sIgphwSWKRxK0mvh6ERxKqIt1
xJEJO74EykXZV4oNJ8sjAjEA3J9r2ZghVhGN6V8DnQrTk24Td0E8hU8AcP0FVP+8
PQm/g/aXf2QQkQT+omdHVEJrAjEAy0pL0EBH6EVS98evDCBtQw22OZT52qXlAwZ2
gyTriKFVoqjeEjt3SZKKqXHSApP/AjBLpF99zcJJZRq2abgYlf9lv1chkrWqDHUu
DZttmYJeEfiFBBavVYIF1dOlZT0G8jMCMBc7sOSZodFnAiryP+Qg9otSBjJ3bQML
pSTqy7c3a2AScC/YyOwkDaICHnnD3XyjMwIxALRzl0tQEKMXs6hH8ToUdlLROCrP
EhQ0wahUTCk1gKA4uPD6TMTChavbh4K63OvbKg==
-----END RSA PRIVATE KEY-----"""


class AvaSSHProtocol(recvline.HistoricRecvLine):
    files_list = []
    prompt = None
    ps = ('', '... ')
    location = "~"
    welcome = """
    Welcome to Ubuntu Xenial Xerus (development branch) (GNU/Linux 3.13.0-24-generic x86_64)

    * Documentation:  https://help.ubuntu.com/
    Last login: Sat Feb 20 11:10:00 2016 from 37.98.114.50
    """

    protocolVersion = '2.0'
    version = 'OpenSSH_6.6.1p1'
    comment = ''
    ourVersionString = ('SSH-' + protocolVersion + '-' + version + ' '
            + comment).strip()

    # C{none} is supported as cipher and hmac. For security they are disabled
    # by default. To enable them, subclass this class and add it, or do:
    # SSHTransportBase.supportedCiphers.append('none')
    # List ordered by preference.
    supportedCiphers = ['aes256-ctr', 'aes256-cbc', 'aes192-ctr', 'aes192-cbc',
                        'aes128-ctr', 'aes128-cbc', 'cast128-ctr',
                        'cast128-cbc', 'blowfish-ctr', 'blowfish-cbc',
                        '3des-ctr', '3des-cbc'] # ,'none']
    supportedMACs = [
        'hmac-sha2-512',
        'hmac-sha2-256',
        'hmac-sha1',
        'hmac-md5',
        # `none`,
        ]

    supportedKeyExchanges = _kex.getSupportedKeyExchanges()
    supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
    supportedCompressions = ['none', 'zlib']
    supportedLanguages = ()
    supportedVersions = ('1.99', '2.0')
    isClient = False
    gotVersion = False
    buf = ''
    outgoingPacketSequence = 0
    incomingPacketSequence = 0
    outgoingCompression = None
    incomingCompression = None
    sessionID = None
    service = None

    # There is no key exchange activity in progress.
    _KEY_EXCHANGE_NONE = '_KEY_EXCHANGE_NONE'

    # Key exchange is in progress and we started it.
    _KEY_EXCHANGE_REQUESTED = '_KEY_EXCHANGE_REQUESTED'

    # Key exchange is in progress and both sides have sent KEXINIT messages.
    _KEY_EXCHANGE_PROGRESSING = '_KEY_EXCHANGE_PROGRESSING'

    # There is a fourth conceptual state not represented here: KEXINIT received
    # but not sent.  Since we always send a KEXINIT as soon as we get it, we
    # can't ever be in that state.

    # The current key exchange state.
    _keyExchangeState = _KEY_EXCHANGE_NONE
    _blockedByKeyExchange = None

    def __init__(self, user):
        self.user = user
        self.make_prompt()

    def make_prompt(self):
        self.prompt = self.user.username + "@" + "linux-srv1:" + self.location + "$ "

    def makeConnection(self, terminal):
        self.terminal = terminal
        self.connectionMade()

    def connectionMade(self):
        # A list containing the characters making up the current line
        self.lineBuffer = []

        # A zero-based (wtf else?) index into self.lineBuffer.
        # Indicates the current cursor position.
        self.lineBufferIndex = 0

        t = self.terminal
        # A map of keyIDs to bound instance methods.
        self.keyHandlers = {
            t.LEFT_ARROW: self.handle_LEFT,
            t.RIGHT_ARROW: self.handle_RIGHT,
            t.TAB: self.handle_TAB,

            # Both of these should not be necessary, but figuring out
            # which is necessary is a huge hassle.
            '\r': self.handle_RETURN,
            '\n': self.handle_RETURN,

            t.BACKSPACE: self.handle_BACKSPACE,
            t.DELETE: self.handle_DELETE,
            t.INSERT: self.handle_INSERT,
            t.HOME: self.handle_HOME,
            t.END: self.handle_END}

        self.initializeScreen()

        self.historyLines = []
        self.historyPosition = 0

        self.keyHandlers.update({t.UP_ARROW: self.handle_UP,
                                 t.DOWN_ARROW: self.handle_DOWN})
        self.terminal.write(self.welcome)
        self.terminal.nextLine()
        self.showPrompt()
        self.search_attacker().addCallback(self.im_online)
        # reactor.callFromThread(self.im_online)

    def search_attacker(self):
        return SSHAttacker.find(
            where=['ip = ?', self.terminal.transport.getPeer().address.host], limit=1
            )

    def im_online(self, attacker):
        attacker.is_online = True
        attacker.save()


    def sendKexInit(self):
        """
        Send a I{KEXINIT} message to initiate key exchange or to respond to a
        key exchange initiated by the peer.

        @raise RuntimeError: If a key exchange has already been started and it
            is not appropriate to send a I{KEXINIT} message at this time.

        @return: C{None}
        """
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            raise RuntimeError(
                "Cannot send KEXINIT while key exchange state is %r" % (
                    self._keyExchangeState,))

        self.ourKexInitPayload = (chr(MSG_KEXINIT) +
               randbytes.secureRandom(16) +
               NS(','.join(self.supportedKeyExchanges)) +
               NS(','.join(self.supportedPublicKeys)) +
               NS(','.join(self.supportedCiphers)) +
               NS(','.join(self.supportedCiphers)) +
               NS(','.join(self.supportedMACs)) +
               NS(','.join(self.supportedMACs)) +
               NS(','.join(self.supportedCompressions)) +
               NS(','.join(self.supportedCompressions)) +
               NS(','.join(self.supportedLanguages)) +
               NS(','.join(self.supportedLanguages)) +
               '\000' + '\000\000\000\000')
        self.sendPacket(MSG_KEXINIT, self.ourKexInitPayload[1:])
        self._keyExchangeState = self._KEY_EXCHANGE_REQUESTED
        self._blockedByKeyExchange = []

    def sendPacket(self, messageType, payload):
        """
        Sends a packet.  If it's been set up, compress the data, encrypt it,
        and authenticate it before sending.  If key exchange is in progress and
        the message is not part of key exchange, queue it to be sent later.

        @param messageType: The type of the packet; generally one of the
                            MSG_* values.
        @type messageType: C{int}
        @param payload: The payload for the message.
        @type payload: C{str}
        """
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            if not self._allowedKeyExchangeMessageType(messageType):
                self._blockedByKeyExchange.append((messageType, payload))
                return

        payload = chr(messageType) + payload
        if self.outgoingCompression:
            payload = (self.outgoingCompression.compress(payload)
                       + self.outgoingCompression.flush(2))
        bs = self.currentEncryptions.encBlockSize
        # 4 for the packet length and 1 for the padding length
        totalSize = 5 + len(payload)
        lenPad = bs - (totalSize % bs)
        if lenPad < 4:
            lenPad = lenPad + bs
        packet = (struct.pack('!LB',
                              totalSize + lenPad - 4, lenPad) +
                  payload + randbytes.secureRandom(lenPad))
        encPacket = (
            self.currentEncryptions.encrypt(packet) +
            self.currentEncryptions.makeMAC(
                self.outgoingPacketSequence, packet))
        self.terminal.transport.write(encPacket)
        self.outgoingPacketSequence += 1

    def initializeScreen(self):
        self.setInsertMode()

    def showPrompt(self):
        self.terminal.write(self.prompt)

    def getCommandFunc(self, cmd):
        return getattr(self, 'do_' + cmd, None)

    def lineReceived(self, line):
        line = line.strip()
        if line:
            cmdAndArgs = line.split()
            cmd = cmdAndArgs[0]
            args = cmdAndArgs[1:]
            func = self.getCommandFunc(cmd)
            if func:
                status = True
                try:
                    func(*args)
                except Exception, e:
                    status = False
                    self.terminal.write("Error: %s" % e)
                    self.terminal.nextLine()
            else:
                status = False
                self.terminal.write(cmd + ": command not found")
                self.terminal.nextLine()
            self.search_attacker().addCallback(self.put_data, cmd, args, status)
        self.showPrompt()

    # def start_log_command(self, cmd, cmd_args, status):
    #     SSHAttacker.find(
    #         where=['ip = ?', self.terminal.transport.getPeer().address.host], limit=1
    #         )

    def put_data(self, attacker, cmd, cmd_args, status):

        try:
            attacked_time = time.time()
            command = SSHAttackerCommand()
            command.attacker_id = attacker.id
            command.command = "%s:%s" % (cmd, cmd_args)
            command.status = status
            command.timestamp = attacked_time
            command.save()
        except Exception as e:
            syslog_msg = 'date={date} time={time} AvaPotProtocol={AvaPotProtocol} Has Failed to Insert Into Database Because : {error}\n' \
                .format(date=datetime.datetime.fromtimestamp(attacked_time).strftime('%Y-%m-%d'),
                        time=datetime.datetime.fromtimestamp(attacked_time).strftime('%H:%M:%S'),
                        AvaPotProtocol='ssh',
                        error=str(e)
                        )
            insertSysLog(syslog_msg)
        try:
            syslog_msg ='date={date} time={time} AvaPotProtocol={AvaPotProtocol} ip={ip} type_cmd={type_cmd} username={username}'\
                    'password={password}  status={status} command={command}\n'\
                .format(date=datetime.datetime.fromtimestamp(attacked_time).strftime('%Y-%m-%d'),
                        time=datetime.datetime.fromtimestamp(attacked_time).strftime('%H:%M:%S'),
                        AvaPotProtocol='ssh',
                        ip=self.client_address[0],
                        type_cmd="command",
                        username='',
                        password='',
                        status=status,
                        command=command
                        )
            insertSysLog(syslog_msg)
        except Exception as e:
            print str(e)
    def do_help(self):
        publicMethods = filter(
            lambda funcname: funcname.startswith('do_'), dir(self))
        commands = [cmd.replace('do_', '', 1) for cmd in publicMethods]
        self.terminal.write("Commands: " + " ".join(commands))
        self.terminal.nextLine()

    def do_echo(self, *args):
        self.terminal.write(" ".join(args))
        self.terminal.nextLine()

    def do_whoami(self):
        self.terminal.write(self.user.username)
        self.terminal.nextLine()

    def do_cd(self, *args):
        self.location = args[0]
        self.make_prompt()
        self.terminal.nextLine()

    def do_exit(self):
        self.terminal.write("logout\n")
        self.terminal.transport.loseConnection()

    def do_clear(self):
        self.terminal.reset()


    def do_ls(self, *args):
        """list directories

        this aint working now, just provides testing.
        """
        arg_list, folder_list = self.get_args(args)
        if not arg_list:
            # No arguments, just show the folders
            for file in self.files_list:
                _result = "%s\t"%(file['name'])


        _end_result = _result + '\n'
        self.terminal.write(_end_result)


    def do_mkdir(self, *args):
        """mkdir command

        we have implemented the mkdir command. we are reciving
        an arguments list an parse it. we know that the very
        last part is folder name to be created and anything
        between is the arguments. we split the input argument
        based on this, and try to work it out for different commands.
        """
        arg_list, folder_list = self.get_args(args)
        if folder_list:
            for folder in folder_list:
                new_folder = {'file_type': 'folder',
                              'name': folder,
                              'create_date': datetime.datetime.now(),
                              'permission': 'drwxr-xr-x.'}
                self.files_list.append(new_folder)
        if arg_list:
            for arg in arg_list:
                if 'v' in arg or '--verbose' in arg:
                    # Verbose Mode
                    if folder_list:
                        for file in folder_list:
                            _result = 'mkdir: created directory `%s`\n'% (file)
                            self.terminal.write(_result)
                    else:
                        _result = MISSING_OPERAND
                        self.terminal.write(_result)
                if 'm' in arg or '--mode' in arg:
                    # CHMOD Mode
                    if folder_list:
                        _result = 'chmod mode on\n'
                    else:
                        _result = MISSING_ARGUMENT
                    self.terminal.write(_result)
                if 'p' in arg or '--parent' in arg:
                    # Parent Mode
                    if folder_list:
                        _result = 'parent mode on\n'
                    else:
                        _result = MISSING_OPERAND
                    self.terminal.write(_result)
                if 'help' in arg:
                    # HELP Mode
                    self.terminal.write(HELP_INFO)
                if 'z' in arg:
                    # SELINUX mode thing!
                    self.terminal.write("selinux mode on\n")
                if 'version' in arg:
                    # Version output
                    self.terminal.write(VERSION_INFO)


    def get_args(self, args):
        """proccess the arguments

        this will help us with reading and parsing the arguments
        comming in from command proccessor. we would get a list
        of arguments and return the arguments and file/folder
        names that we proccessed.
        """
        arg_list = []
        file_list = []
        for arg in args:
            if '-' in arg:
                arg_list.append(arg)
            else:
                file_list.append(arg)
        return arg_list, file_list


def getRSAKeys():
    with open('/opt/avapot/ssh/id_rsa') as privateBlobFile:
        privateBlob = privateBlobFile.read()
        privateKey = keys.Key.fromString(data=privateBlob)

    with open('/opt/avapot/ssh/id_rsa.pub') as publicBlobFile:
        publicBlob = publicBlobFile.read()
        publicKey = keys.Key.fromString(data=publicBlob)

    return publicKey, privateKey

class AvaSSHFactory(factory.SSHFactory):
    protocol = AvaSSHServerTransport

    publicKeys = {
        'ssh-rsa': keys.Key.fromString(data=publicKey)
    }
    privateKeys = {
        'ssh-rsa': keys.Key.fromString(data=privateKey)
    }
    services = {
        'ssh-userauth': AvaSSHAuthServer,
        'ssh-connection': connection.SSHConnection
    }


class AvaSSHAvatar(avatar.ConchUser):
    implements(ISession)

    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session': session.SSHSession})

    def openShell(self, protocol): # <<< ? koja estefade mishe ?
        serverProtocol = insults.ServerProtocol(AvaSSHProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        return None

    def execCommand(self, protocol, cmd):
        raise NotImplementedError()

    def closed(self):
        pass

class AvaSSHRealm(object):
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IConchUser in interfaces:
            return interfaces[0], AvaSSHAvatar(avatarId), lambda: None
        else:
            raise NotImplementedError("No supported interfaces found.")


DH_GENERATOR, DH_PRIME = _kex.getDHGeneratorAndPrime(
    'diffie-hellman-group1-sha1')


MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_UNIMPLEMENTED = 3
MSG_DEBUG = 4
MSG_SERVICE_REQUEST = 5
MSG_SERVICE_ACCEPT = 6
MSG_KEXINIT = 20
MSG_NEWKEYS = 21
MSG_KEXDH_INIT = 30
MSG_KEXDH_REPLY = 31
MSG_KEX_DH_GEX_REQUEST_OLD = 30
MSG_KEX_DH_GEX_REQUEST = 34
MSG_KEX_DH_GEX_GROUP = 31
MSG_KEX_DH_GEX_INIT = 32
MSG_KEX_DH_GEX_REPLY = 33



DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1
DISCONNECT_PROTOCOL_ERROR = 2
DISCONNECT_KEY_EXCHANGE_FAILED = 3
DISCONNECT_RESERVED = 4
DISCONNECT_MAC_ERROR = 5
DISCONNECT_COMPRESSION_ERROR = 6
DISCONNECT_SERVICE_NOT_AVAILABLE = 7
DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8
DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9
DISCONNECT_CONNECTION_LOST = 10
DISCONNECT_BY_APPLICATION = 11
DISCONNECT_TOO_MANY_CONNECTIONS = 12
DISCONNECT_AUTH_CANCELLED_BY_USER = 13
DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
DISCONNECT_ILLEGAL_USER_NAME = 15

if __name__ == '__main__':
    sshFactory = AvaSSHFactory()
    sshFactory.portal = portal.Portal(AvaSSHRealm())
    sshFactory.portal.registerChecker(InDataBaseChecker())
    pubKey, privKey = getRSAKeys()
    sshFactory.publicKeys = {'ssh-rsa': pubKey}
    sshFactory.privateKeys = {'ssh-rsa': privKey}
    reactor.listenTCP(8022, sshFactory)
    reactor.run()
