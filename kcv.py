# hsm-key-parts - HSM XOR key parts utilities
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

TYPES = ["3des", "aes"]


from Crypto.Cipher import AES, DES3
try:
	from Crypto.Hash import CMAC
	TYPES.extend(["3des-cmac", "aes-cmac"])
except ImportError:
	pass
import codecs


def kcv(key, type):
	key = bytes.fromhex(key)
	if type not in TYPES:
		raise Exception(f"Unsupported KCV type {type}")

	type = type.split("-")
	cipher = {
		"3des": DES3,
		"aes": AES
	}[type[0]]

	assert len(key) in cipher.key_size, f"Invalid key length {len(key)}"

	if len(type) == 1:
		iv = {"3des": 8, "aes": 16}[type[0]]
		eobj = cipher.new(key, cipher.MODE_CBC, b"\x00" * cipher.block_size)
		return codecs.encode(eobj.encrypt(b"\x00" * cipher.block_size), "hex").decode("us-ascii").upper()

	if type[1] == "cmac":
		cobj = CMAC.new(key, ciphermod=cipher)
		cobj.update(b"\x00" * cipher.block_size)
		return cobj.hexdigest().upper()
