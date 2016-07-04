#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import re
import base64
import binascii

import cmath as math
range = xrange

def factors(n):
	"Yield every pair of factors of n (x,y where n/x == y and n/y == x), except for (1,n) and (n,1)."
	limit = math.sqrt(n).real
	if n == 1:
		yield (1, 1)
		return
	for i in range(1, int(limit + 1)):
		if n % i == 0:
			pair = (i, n/i)
			yield pair

			opposite_pair = (pair[1], pair[0])
			#If n is square, one of the pairs will be (sqrt, sqrt). We want to yield that only once. All other pairs, we want to yield both ways round.
			if pair != opposite_pair:
				yield opposite_pair

def except_one(pairs):
	"Given a sequence of pairs (x, y), yield every pair where neither x nor y is 1."
	for pair in pairs:
		if 1 not in pair:
			yield pair

MD5_exp = re.compile(r'^MD5 \(.*\) = ([0-9a-fA-f]+)')
RSA_exp = re.compile(r'^RSA key fingerprint is (?:MD5:)?([:0-9a-fA-f]+)\.')
ECDSA_exp = re.compile(r'^ECDSA key fingerprint is SHA256:([+/0-9a-zA-Z]+)\.')
more_base64_padding_than_anybody_should_ever_need = '=' * 64

def extract_hash_from_line(input_line):
	"Returns a tuple of the extracted hash as hex, and whether it was originally hex (vs, say, base64). The hash may be None if none was found in the input."
	if input_line[:1] == 'M':
		match = MD5_exp.match(input_line)
		if match:
			return match.group(1), True
		else:
			return '', False
	elif input_line[:1] == 'R':
		match = RSA_exp.match(input_line)
		if match:
			return match.group(1), True
		else:
			return '', False
	elif input_line[:1] == 'E':
		match = ECDSA_exp.match(input_line)
		if match:
			b64str = match.group(1)
			# Pacify the base64 module, which wants *some* padding (at least sometimes) but doesn't care how much.
			b64str += more_base64_padding_than_anybody_should_ever_need
			# Re-encode to hex for processing downstream. Arguably a refactoring opportunity…
			return binascii.b2a_hex(base64.b64decode(b64str)), False

	if input_line:
		try:
			hash, not_the_hash = input_line.split(None, 1)
		except ValueError:
			# Insufficient fields. This line doesn't contain any whitespace. Use the entire line.
			hash = input_line
		hash = hash.strip().replace('-', '')

		try:
			int(hash, 16)
		except ValueError:
			# Not a hex number.
			return None, False
		else:
			return hash, True

def parse_hex(hex):
	hex = hex.lstrip(':-')
	while hex:
		byte_hex, hex = hex[:2], hex[2:].lstrip(':-')
		yield int(byte_hex, 16)

def hash_to_pic(hash, only_ever_one_line=False, represent_as_hex=False):
	bytes = parse_hex(hash)
	def fgcolor(idx):
		idx = ((idx >> 4) & 0xf)
		# 90 is bright foreground; 30 is dull foreground.
		if idx < 0x8:
			base = 30
		else:
			base = 90
			idx = idx - 0x8
		return '\x1b[{0}m'.format(base + idx)
	def bgcolor(idx):
		idx = (idx & 0xf)
		# 100 is bright background; 40 is dull background.
		if idx < 0x8:
			base = 40
		else:
			base = 100
			idx = idx - 0x8
		return '\x1b[{0}m'.format(base + idx)
	bold = '\x1b[1m'
	reset = '\x1b[0m'
	characters = list('0123456789abcdef') if represent_as_hex else [
		'▚',
		'▞',
		'▀',
		'▌',
	]
	if not only_ever_one_line:
		pairs = list((w, h) for (w, h) in except_one(factors(len(hash) / 2)) if w >= h)
		if not pairs:
			# Prefer (w, 1) over (1, h) if we have that choice.
			pairs = list((w, h) for (w, h) in factors(len(hash) / 2) if w >= h)

	output_chunks = []
	last_byte = 0
	character_idx = None
	for b in bytes:
		def find_character(b):
			character_idx = b % len(characters)
			return characters[character_idx]
		if not represent_as_hex:
			output_chunks.append(fgcolor(b) + bgcolor(b) + find_character(b))
		else:
			output_chunks.append(fgcolor(b) + bgcolor(b) + find_character(b >> 4) + find_character(b & 0xf))
		last_byte = b

	if only_ever_one_line:
		pixels_per_row, num_rows = len(hash) / 2, 1
	else:
		pixels_per_row, num_rows = pairs[last_byte % len(pairs)]
	while output_chunks:
		yield bold + ''.join(output_chunks[:pixels_per_row]) + reset
		del output_chunks[:pixels_per_row]

if __name__ == '__main__':
	run_tests = False
	if run_tests:
		# A square number. Should contain a diagonal pair (in this case, (16,16)).
		factors_of_256 = set(factors(256))
		assert factors_of_256 == set([(256, 1), (16, 16), (8, 32), (2, 128), (64, 4), (1, 256), (32, 8), (128, 2), (4, 64)])

		# A rectangular number: not square, but still composite. No diagonal pair here.
		factors_of_12 = set(factors(12))
		assert factors_of_12 == set([(2, 6), (12, 1), (1, 12), (6, 2), (4, 3), (3, 4)])

		assert (1, 256) in factors_of_256
		assert (256, 1) in factors_of_256
		assert (1, 256) not in except_one(factors_of_256)
		assert (256, 1) not in except_one(factors_of_256)

		# A prime number. Should have exactly one pair of factors.
		factors_of_5 = set(factors(5))
		assert factors_of_5 == set([(1, 5), (5, 1)])

		assert list(parse_hex('ab15e')) == [0xab, 0x15, 0x0e]
		assert list(parse_hex(':::ab:15:e')) == [0xab, 0x15, 0x0e]

		assert extract_hash_from_line('RSA key fingerprint is b8:79:03:7d:00:44:98:6e:67:a0:59:1a:01:21:36:38.\n') == ('b8:79:03:7d:00:44:98:6e:67:a0:59:1a:01:21:36:38', True)
		assert extract_hash_from_line('RSA key fingerprint is b8:79:03:7d:00:44:98:6e:67:a0:59:1a:01:21:36:38.') == ('b8:79:03:7d:00:44:98:6e:67:a0:59:1a:01:21:36:38', True)
		#Alternate output example from https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Authentication_Keys :
		assert extract_hash_from_line('RSA key fingerprint is MD5:10:4a:ec:d2:f1:38:f7:ea:0a:a0:0f:17:57:ea:a6:16.') == ('10:4a:ec:d2:f1:38:f7:ea:0a:a0:0f:17:57:ea:a6:16', True)
		# Also from https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Authentication_Keys :
		assert extract_hash_from_line('ECDSA key fingerprint is SHA256:LPFiMYrrCYQVsVUPzjOHv+ZjyxCHlVYJMBVFerVCP7k.\n') == ('2cf162318aeb098415b1550fce3387bfe663cb10879556093015457ab5423fb9', False), extract_hash_from_line('ECDSA key fingerprint is SHA256:LPFiMYrrCYQVsVUPzjOHv+ZjyxCHlVYJMBVFerVCP7k.\n')
		assert extract_hash_from_line('ECDSA key fingerprint is SHA256:LPFiMYrrCYQVsVUPzjOHv+ZjyxCHlVYJMBVFerVCP7k.') == ('2cf162318aeb098415b1550fce3387bfe663cb10879556093015457ab5423fb9', False), extract_hash_from_line('ECDSA key fingerprint is SHA256:LPFiMYrrCYQVsVUPzjOHv+ZjyxCHlVYJMBVFerVCP7k.')
		#UUID
		assert extract_hash_from_line('E6CD379E-12CD-4E00-A83A-B06E74CF03B8') == ('E6CD379E12CD4E00A83AB06E74CF03B8', True), extract_hash_from_line('E6CD379E-12CD-4E00-A83A-B06E74CF03B8')
		assert extract_hash_from_line('e6cd379e-12cd-4e00-a83a-b06e74cf03b8') == ('e6cd379e12cd4e00a83ab06e74cf03b8', True), extract_hash_from_line('e6cd379e-12cd-4e00-a83a-b06e74cf03b8')

		assert extract_hash_from_line('MD5 (hashvis.py) = e21c7b846f76826d52a0ade79ef9cb49\n') == ('e21c7b846f76826d52a0ade79ef9cb49', True)
		assert extract_hash_from_line('MD5 (hashvis.py) = e21c7b846f76826d52a0ade79ef9cb49') == ('e21c7b846f76826d52a0ade79ef9cb49', True)
		assert extract_hash_from_line('8b948e9c85fdf68f872017d7064e839c  hashvis.py\n') == ('8b948e9c85fdf68f872017d7064e839c', True)
		assert extract_hash_from_line('8b948e9c85fdf68f872017d7064e839c  hashvis.py') == ('8b948e9c85fdf68f872017d7064e839c', True)
		assert extract_hash_from_line('2c9997ce32cb35823b2772912e221b350717fcb2d782c667b8f808be44ae77ba1a7b94b4111e386c64a2e87d15c64a2fc2177cd826b9a0fba6b348b4352ed924  hashvis.py\n') == ('2c9997ce32cb35823b2772912e221b350717fcb2d782c667b8f808be44ae77ba1a7b94b4111e386c64a2e87d15c64a2fc2177cd826b9a0fba6b348b4352ed924', True)
		assert extract_hash_from_line('2c9997ce32cb35823b2772912e221b350717fcb2d782c667b8f808be44ae77ba1a7b94b4111e386c64a2e87d15c64a2fc2177cd826b9a0fba6b348b4352ed924  hashvis.py') == ('2c9997ce32cb35823b2772912e221b350717fcb2d782c667b8f808be44ae77ba1a7b94b4111e386c64a2e87d15c64a2fc2177cd826b9a0fba6b348b4352ed924', True)
		assert extract_hash_from_line('#!/usr/bin/python\n')[0] is None

		# Protip: Use vis -co to generate these.
		(line,) = hash_to_pic('78', represent_as_hex=True)
		assert line == '\033[1m\033[37m\033[100m78\033[0m', repr(line)
		(line,) = hash_to_pic('7f', represent_as_hex=True)
		assert line == '\033[1m\033[37m\033[107m7f\033[0m', repr(line)
		assert list(hash_to_pic('aebece')) != list(hash_to_pic('deeefe')), (list(hash_to_pic('aebece')), list(hash_to_pic('deeefe')))
		assert list(hash_to_pic('eaebec')) != list(hash_to_pic('edeeef')), (list(hash_to_pic('eaebec')), list(hash_to_pic('edeeef')))
		sys.exit(0)

	import argparse
	parser = argparse.ArgumentParser(description="Visualize hexadecimal input (hashes, UUIDs, etc.) as an arrangement of color blocks.")
	parser.add_argument('--one-line', '--oneline', action='store_true', help="Unconditionally produce a rectangle 1 character tall. The default is to choose a pair of width and height based upon one of the bytes of the input.")
	options, args = parser.parse_known_args()

	import fileinput
	for input_line in fileinput.input(args):
		print input_line.rstrip('\n')

		hash, is_hex = extract_hash_from_line(input_line)
		if hash:
			for output_line in hash_to_pic(hash, only_ever_one_line=options.one_line, represent_as_hex=is_hex):
				print output_line
