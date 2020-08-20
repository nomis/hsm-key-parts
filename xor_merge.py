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
import textwrap

import kcv



def merge_parts(keys):
	assert len(keys) > 0, "No key parts provided"

	lengths = set([len(bytes.fromhex(key)) for key in keys])
	assert len(lengths) == 1, f"Key parts must all be the same length: {lengths}"

	keys = [bytes.fromhex(key) for key in keys]
	output = keys[0]
	for i in range(1, len(keys)):
		output = bytes(a ^ b for (a, b) in zip(output, keys[i]))
	return codecs.encode(bytes(output), "hex").upper().decode("us-ascii")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Merge HSM key parts into one using XOR")
	parser.add_argument("keys", metavar="KEY", type=str, nargs="+", help="Key parts")
	parser.add_argument("-k", "--kcv", choices=kcv.TYPES, help="KCV algorithm")

	args = parser.parse_args()

	def _wrap(text, n):
		return " ".join(textwrap.wrap(text, n))

	for i, key in enumerate(args.keys):
		key = " ".join(textwrap.wrap(key, 4))
		if args.kcv:
			print(f"Input {i + 1}: {key} (CCV {_wrap(kcv.kcv(key, args.kcv)[0:6], 2)})")
		else:
			print(f"Input {i + 1}: {key}")

	key = _wrap(merge_parts(args.keys), 4)
	if args.kcv:
		print(f"Output: {key} (KCV {_wrap(kcv.kcv(key, args.kcv)[0:6], 2)})")
	else:
		print(f"Output: {key}")
