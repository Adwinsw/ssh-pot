from utilz.daemon import Daemon
from ssh.server import *

class MiladpotSSHService(Daemon):
    def run(self):
	    sshFactory = MiladSSHFactory()
	    sshFactory.portal = portal.Portal(MiladSSHRealm())
	    sshFactory.portal.registerChecker(InDataBaseChecker())
	    # pubKey, privKey = getRSAKeys()
	    # sshFactory.publicKeys = {'ssh-rsa': pubKey}
	    # sshFactory.privateKeys = {'ssh-rsa': privKey}
	    reactor.listenTCP(22, sshFactory)
	    reactor.run()