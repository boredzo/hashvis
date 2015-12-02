#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

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

def parse_hex(hex):
	while hex:
		byte_hex, hex = hex[:2], hex[2:]
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
		base = 100 if idx > 0x7 else 40
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

	sys.exit(0)

import fileinput

for input_line in fileinput.input():
	hash, other_stuff_including_probably_a_filename = input_line.split(None, 1)

	print other_stuff_including_probably_a_filename.rstrip('\n')
	for output_line in hash_to_pic(hash):
		print output_line
