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
	if input_line[:1] == 'M':
		match = MD5_exp.match(input_line)
		if match:
			return match.group(1)
		else:
			return ''
	elif input_line[:1] == 'R':
		match = RSA_exp.match(input_line)
		if match:
			return match.group(1)
		else:
			return ''
	elif input_line[:1] == 'E':
		match = ECDSA_exp.match(input_line)
		if match:
			b64str = match.group(1)
			# Pacify the base64 module, which wants *some* padding (at least sometimes) but doesn't care how much.
			b64str += more_base64_padding_than_anybody_should_ever_need
			# Re-encode to hex for processing downstream. Arguably a refactoring opportunity…
			return binascii.b2a_hex(base64.b64decode(b64str))
		else:
			return ''
	else:
		try:
			hash, not_the_hash = input_line.split(None, 1)
		except ValueError:
			# Insufficient fields. This line doesn't contain any whitespace. Use the entire line.
			hash = input_line

		try:
			int(hash, 16)
		except ValueError:
			# Not a hex number.
			return None
		else:
			return hash

def parse_hex(hex):
	hex = hex.lstrip(':')
	while hex:
		byte_hex, hex = hex[:2], hex[2:].lstrip(':')
		yield int(byte_hex, 16)

def hash_to_pic(hash):
	bytes = parse_hex(hash)
	def fgcolor(idx):
		idx = ((idx >> 4) & 0xf)
		# 90 is bright foreground; 30 is dull foreground.
		base = 90 if idx > 0x7 else 30
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
	reset = '\x1b[0m'
	characters = [
		'▚',
		'▞',
		'▀',
		'▌',
	]
	pairs = list((w, h) for (w, h) in except_one(factors(len(hash) / 2)) if w >= h)
	if not pairs:
		# Prefer (w, 1) over (1, h) if we have that choice.
		pairs = list((w, h) for (w, h) in factors(len(hash) / 2) if w >= h)

	output_chunks = []
	last_byte = 0
	character_idx = None
	for b in bytes:
		character_idx = b % len(characters)
		output_chunks.append(fgcolor(b) + bgcolor(b) + characters[character_idx])
		last_byte = b

	pixels_per_row, num_rows = pairs[last_byte % len(pairs)]
	while output_chunks:
		yield ''.join(output_chunks[:pixels_per_row]) + reset
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

		assert extract_hash_from_line('RSA key fingerprint is b8:79:03:7d:00:44:98:6e:67:a0:59:1a:01:21:36:38.\n') == 'b8:79:03:7d:00:44:98:6e:67:a0:59:1a:01:21:36:38'
		assert extract_hash_from_line('RSA key fingerprint is b8:79:03:7d:00:44:98:6e:67:a0:59:1a:01:21:36:38.') == 'b8:79:03:7d:00:44:98:6e:67:a0:59:1a:01:21:36:38'
		#Alternate output example from https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Authentication_Keys :
		assert extract_hash_from_line('RSA key fingerprint is MD5:10:4a:ec:d2:f1:38:f7:ea:0a:a0:0f:17:57:ea:a6:16.') == '10:4a:ec:d2:f1:38:f7:ea:0a:a0:0f:17:57:ea:a6:16'
		# Also from https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Authentication_Keys :
		assert extract_hash_from_line('ECDSA key fingerprint is SHA256:LPFiMYrrCYQVsVUPzjOHv+ZjyxCHlVYJMBVFerVCP7k.\n') == '2cf162318aeb098415b1550fce3387bfe663cb10879556093015457ab5423fb9', extract_hash_from_line('ECDSA key fingerprint is SHA256:LPFiMYrrCYQVsVUPzjOHv+ZjyxCHlVYJMBVFerVCP7k.\n')
		assert extract_hash_from_line('ECDSA key fingerprint is SHA256:LPFiMYrrCYQVsVUPzjOHv+ZjyxCHlVYJMBVFerVCP7k.') == '2cf162318aeb098415b1550fce3387bfe663cb10879556093015457ab5423fb9', extract_hash_from_line('ECDSA key fingerprint is SHA256:LPFiMYrrCYQVsVUPzjOHv+ZjyxCHlVYJMBVFerVCP7k.')

		assert extract_hash_from_line('MD5 (hashvis.py) = e21c7b846f76826d52a0ade79ef9cb49\n') == 'e21c7b846f76826d52a0ade79ef9cb49'
		assert extract_hash_from_line('MD5 (hashvis.py) = e21c7b846f76826d52a0ade79ef9cb49') == 'e21c7b846f76826d52a0ade79ef9cb49'
		assert extract_hash_from_line('8b948e9c85fdf68f872017d7064e839c  hashvis.py\n') == '8b948e9c85fdf68f872017d7064e839c'
		assert extract_hash_from_line('8b948e9c85fdf68f872017d7064e839c  hashvis.py') == '8b948e9c85fdf68f872017d7064e839c'
		assert extract_hash_from_line('2c9997ce32cb35823b2772912e221b350717fcb2d782c667b8f808be44ae77ba1a7b94b4111e386c64a2e87d15c64a2fc2177cd826b9a0fba6b348b4352ed924  hashvis.py\n') == '2c9997ce32cb35823b2772912e221b350717fcb2d782c667b8f808be44ae77ba1a7b94b4111e386c64a2e87d15c64a2fc2177cd826b9a0fba6b348b4352ed924'
		assert extract_hash_from_line('2c9997ce32cb35823b2772912e221b350717fcb2d782c667b8f808be44ae77ba1a7b94b4111e386c64a2e87d15c64a2fc2177cd826b9a0fba6b348b4352ed924  hashvis.py') == '2c9997ce32cb35823b2772912e221b350717fcb2d782c667b8f808be44ae77ba1a7b94b4111e386c64a2e87d15c64a2fc2177cd826b9a0fba6b348b4352ed924'
		assert extract_hash_from_line('#!/usr/bin/python\n') is None

		(line,) = hash_to_pic('78')
		assert line == '\x1b[37m\x1b[100m\xe2\x96\x9a\x1b[0m', repr(line)
		(line,) = hash_to_pic('7f')
		assert line == '\x1b[37m\x1b[107m\xe2\x96\x8c\x1b[0m', repr(line)
		sys.exit(0)

	import fileinput

	for input_line in fileinput.input():
		print input_line.rstrip('\n')

		hash = extract_hash_from_line(input_line)
		if hash:
			for output_line in hash_to_pic(hash):
				print output_line
