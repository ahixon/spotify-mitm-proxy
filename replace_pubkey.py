#!/usr/bin/env python2

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from crypto import bin2bn, bn2bin

import shutil
import sys

old_key = 'ACE0460BFFC230AFF46BFEC3BFBF863DA191C6CC336C93A14FB3B01612ACAC6AF180E7F614D9429DBE2E346643E362D2327A1A0D923BAEDD1402B18155056104D52C96A44C1ECC024AD4B20C001F17EDC22FC43521C8F0CBAED2ADD72B0F9DB3C5321A2AFE59F35A0DAC68F1FA621EFB2C8D0CB7392D9247E3D7351A6DBD24C2AE255B88FFAB73298A0BCCCD0C58673189E8BD3480784A5FC96B899D956BFC86D74F33A6781796C9C32D0D32A5ABCD0527E2F710A39613C42F99C027BFED049C3C275804B6B219F9C12F02E94863ECA1B642A09D4825F8B39DD0E86AF9484DA1C2BA863042EA9DB3086C190E48B39D66EB0006A25AEEA11B13873CD719E655BD'
old_key_binary = old_key.decode('hex')

def load_new_key():
	with open("ourserver_private_key.pem", "rb") as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)

		assert private_key.public_key().key_size == 2048
		new_pubkey_binary = bn2bin(private_key.public_key().public_numbers().n)
		assert len(new_pubkey_binary) == 256

		return new_pubkey_binary

def fix(src_fname, dest_fname=None, backup_fname=None):
	if not dest_fname:
		dest_fname = src_fname.replace('.exe', '_patched.exe')

	with open(src_fname, 'rb') as f:
		data = f.read()

		print 'searching for old public key', old_key.lower()
		first_offset = data.find(old_key_binary)

		if first_offset == -1:
			print 'did not find key in input file'
			return False

		# ensure only one match
		assert data.count(old_key_binary, first_offset + 1) == 0

		print 'found at offset', first_offset

		new_pubkey_binary = load_new_key()

		print 'injecting new public key', new_pubkey_binary.encode('hex')
		fixed_data = data.replace(old_key_binary, new_pubkey_binary)

	if backup_fname is not None:
		shutil.copy(src_fname, backup_fname)
		print 'backed up to', backup_fname

	print 'saving to', dest_fname
	with open(dest_fname, 'wb') as f:
		f.write(fixed_data)

	return True

def main():
	arg0 = sys.argv.pop(0)

	if len(sys.argv) < 1 or len(sys.argv) > 2:
		sys.stderr.write('usage: %s inputbin [outputbin]\n' % arg0)
		sys.exit(1)

	infile = sys.argv.pop(0)
	backup = False

	if sys.argv:
		outfile = sys.argv.pop(0)
	else:
		print 'replacing input file', infile
		outfile = infile
		backup = True

	if backup:
		backup_fname = infile + '.bak'
	else:
		backup_fname = None

	if not fix(infile, outfile, backup_fname):
		print 'failed to patch binary'
		sys.exit(2)

if __name__ == '__main__':
	main()