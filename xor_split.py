#!/usr/bin/env python3
# hsm-key-parts - HSM key parts utilities
# Copyright 2020  Simon Arlott
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import binascii
import codecs
import secrets
import textwrap

import kcv
import xor_merge


# Avoid using 2ABC and 3DEF on a phone-style keypad
_TEST_MAP = {
	0x0: (0x6, 0x6),
	0x1: (0x4, 0x5),
	0x2: (0x7, 0x5),
	0x3: (0x7, 0x4),

	0x4: (0x1, 0x5),
	0x5: (0x1, 0x4),
	0x6: (0x7, 0x1),
	0x7: (0x1, 0x6),

	0x8: (0x1, 0x9),
	0x9: (0x1, 0x8),
	0xA: (0x8, 0x2),
	0xB: (0x8, 0x3),

	0xC: (0x8, 0x4),
	0xD: (0x8, 0x5),
	0xE: (0x9, 0x7),
	0xF: (0x9, 0x6),
}
assert [k == v[0] ^ v[1] for (k, v) in _TEST_MAP.items()]


def split_parts(key, parts, test):
	assert parts >= 1, "Must have at least one key part"

	key = bytes.fromhex(key)

	if parts == 1:
		keys = [key]
	elif test:
		keys = [[0 for j in range(len(key))] for i in range(parts)]

		for i in range(len(key)):
			h = (key[i] & 0xF0) >> 4
			l = key[i] & 0x0F

			h = [_TEST_MAP[h][0], _TEST_MAP[h][1], 0]
			l = [_TEST_MAP[l][0], _TEST_MAP[l][1], 0]

			if parts > 2:
				# It is not possible to create A and B in two parts
				# without using 2 or 3 (but this is ok because they
				# are interleaved). When there are more than 2 parts
				# they need to be split up again.
				h[1:2] = _TEST_MAP[h[1]]
				l[1:2] = _TEST_MAP[l[1]]

			for j in range(0, min(3, parts)):
				keys[(min(3, parts) * i + j) % parts][i] |= h[j] << 4
				keys[(min(3, parts) * i + j + 1) % parts][i] |= l[j]

		keys = [bytes(part) for part in keys]

		# There should be no repetitions of 2 or 3
		for part in keys:
			part = codecs.encode(bytes(key), "hex").upper().decode("us-ascii")
			assert "22" not in part, part
			assert "33" not in part, part
	else:
		keys = [None for i in range(parts)]
		rand = [secrets.token_bytes(len(key)) for i in range(parts)]

		keys[0] = rand[0] # Even number of parts starts with random data
		for i in range(~parts & 1, parts): # Odd number of parts are all constructed the same way
			# Each part is the key XOR with the random data for the other parts
			keys[i] = key
			for j in filter(lambda x: x != i, range(parts)):
				keys[i] = bytes(a ^ b for (a, b) in zip(keys[i], rand[j]))

	parts = [codecs.encode(bytes(key), "hex").upper().decode("us-ascii") for key in keys]
	assert bytes.fromhex(xor_merge.merge_parts(parts)) == key, "Split parts do not recombine to the same key"
	return parts


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Split key into XOR parts for an HSM")
	parser.add_argument("keys", metavar="KEY", type=str, nargs="+", help="input key parts")
	parser.add_argument("-p", "--parts", dest="parts", type=int, default=2, help="number of output parts")
	parser.add_argument("-t", "--test", action="store_true", help="simplify test keys for entry on a phone keypad")
	parser.add_argument("-k", "--kcv", choices=kcv.TYPES, help="KCV algorithm")

	args = parser.parse_args()

	def _wrap(text, n):
		return " ".join(textwrap.wrap(text, n))

	if len(args.keys) > 1:
		for i, key in enumerate(args.keys):
			key = " ".join(textwrap.wrap(key, 4))
			if args.kcv:
				print(f"Input {i + 1}: {key} (CCV {_wrap(kcv.kcv(key, args.kcv)[0:6], 2)})")
			else:
				print(f"Input {i + 1}: {key}")

	key = xor_merge.merge_parts(args.keys)
	if args.kcv:
		print(f"Input: {_wrap(key, 4)} (KCV {_wrap(kcv.kcv(key, args.kcv)[0:6], 2)})")
	else:
		print(f"Input: {_wrap(key, 4)}")

	keys = split_parts(key, args.parts, args.test)
	for i, key in enumerate(keys):
		key = _wrap(key, 4)
		if args.kcv:
			print(f"Output {i + 1}: {key} (CCV {_wrap(kcv.kcv(key, args.kcv)[0:6], 2)})")
		else:
			print(f"Output {i + 1}: {key}")

