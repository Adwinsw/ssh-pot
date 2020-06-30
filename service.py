from utilz.daemon import Daemon
from ssh.server import *

class AvapotSSHService(Daemon):
    def run(self):
	    sshFactory = AvaSSHFactory()
	    sshFactory.portal = portal.Portal(AvaSSHRealm())
	    sshFactory.portal.registerChecker(InDataBaseChecker())
	    # pubKey, privKey = getRSAKeys()
	    # sshFactory.publicKeys = {'ssh-rsa': pubKey}
	    # sshFactory.privateKeys = {'ssh-rsa': privKey}
	    reactor.listenTCP(22, sshFactory)
	    reactor.run()