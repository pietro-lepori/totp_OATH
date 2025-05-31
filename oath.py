from argparse import ArgumentParser
from dataclasses import dataclass
from gc import collect as garbage_collect
from getpass import getpass
from subprocess import run
from base64 import b64encode, b64decode, b32decode

argp = ArgumentParser(description = "Add secrets to a db, use them to generate OATH codes")
argp.add_argument("path", metavar = "PATH", nargs = 1, help = "path to file with encrypted secrets")

# crypto functions

def enc(m, password, cipher):
	standards = {"aes" : "-aes-256-cbc", "camellia" : "-camellia-256-cbc"}
	opt = standards[cipher]
	cmd = f"openssl enc -e -a {opt} -salt -iter 150000 -pass stdin"
	ans = run(cmd.split()
		   , capture_output = True, check = True, encoding = "utf8"
		   , input = password + '\n' + m
		   ).stdout
	ans = ans.strip()
	res = b64decode(ans)
	assert res[:8] == b"Salted__"
	res = res[8:]
	res = b64encode(res)
	res = res.decode("utf8")
	return res

def dec(e, password, cipher):
	standards = {"aes" : "-aes-256-cbc", "camellia" : "-camellia-256-cbc"}
	opt = standards[cipher]
	e = b64decode(e)
	e = b"Salted__" + e
	e = b64encode(e)
	e = e.decode("utf8")
	cmd = f"openssl enc -d -a {opt} -salt -iter 150000 -pass stdin"
	ans = run(cmd.split()
		   , capture_output = True, check = True, encoding = "utf8"
		   , input = password + '\n' + e + '\n'
		   ).stdout
	res = ans.split('\n')[-1]
	return res

def kdf(password, salt = None):
	if salt:
		xsalt = b64decode(salt)
		xsalt = xsalt.hex()
	cmd = "openssl enc -e -aes-256-ecb -salt -iter 150000 -pass stdin -P"
	if salt:
		cmd += f" -S {xsalt}"
	ans = run(cmd.split()
		   , capture_output = True, check = True, encoding = "utf8"
		   , input = password + '\n'
		   ).stdout
	res = {}
	for line in ans.split('\n'):
		if '=' in line:
			k, v = line.split('=')
			k = k.strip().lower()
			v = v.strip()
			v = bytes.fromhex(v)
			v = b64encode(v)
			v = v.decode("utf8")
			res[k] = v
	assert len(res) == 2
	if salt:
		assert b64decode(salt) == b64decode(res["salt"])
	return res["salt"], res["key"]

def sha3(x):
	x = str(x)
	cmd = "openssl dgst -hex -sha3-512"
	ans = run(cmd.split()
		   , capture_output = True, check = True, encoding = "utf8"
		   , input = x
		   ).stdout
	res = ans.split()[-1]
	res = bytes.fromhex(res)
	assert len(res) == 64
	res = b64encode(res)
	res = res.decode("utf8")
	return res

def compute_mac(data, password, salt = None):
	salt, key = kdf(password, salt)
	h = sha3(key + data)
	return f"{salt}#{h}"

# OATH functions

def totp(secret, options = None):
	cmd = "oathtool --totp"
	if options:
		cmd += " " + options
	cmd += " -"
	ans = run(cmd.split()
		   , capture_output = True, check = True, encoding = "utf8"
		   , input = secret + '\n'
		   ).stdout
	return ans

# data structures

class Secret(str):
	def hide(self, password):
		e1 = enc(self, password, "camellia")
		e2 = enc(e1, password, "aes")
		return e2
	def totp(self, options = None):
		return totp(str(self), options)
	@classmethod
	def reveal(cls, password, data):
		e1 = dec(data, password, "aes")
		m = dec(e1, password, "camellia")
		return cls(m)

@dataclass(frozen = True)
class Entry:
	name : str
	data : str
	mac : str
	def __post__init__(self):
		if not name:
			raise ValueError("Entry name must be non-empty")
	def __str__(self):
		ret  = f"NAME {self.name}\n"
		ret += f"DATA {self.data}\n"
		ret += f"MAC  {self.mac}\n"
		ret += "\n"
		return ret
	def test(self, password):
		salt = self.mac.split('#')[0]
		x = compute_mac(self.data, password, salt)
		return x == self.mac
	def get_secret(self, password):
		if not self.test(password):
			return None
		secret = Secret.reveal(password, self.data)
		return secret
	@classmethod
	def from_secret(cls, name, secret, password):
		secret = Secret(secret)
		data = secret.hide(password)
		mac = compute_mac(data, password)
		return cls(name, data, mac)

# read file

args = argp.parse_args()
path = args.path[0]
f = open(path, "a+")
f.seek(0)
lines = f.readlines()

entries = []
assert len(lines) % 4 == 0
for i in range(0,len(lines),4):
	group = {k : v for l in lines[i:i+3] for (k, *v) in (l.split(),)}
	assert not lines[i+3].strip()
	name = " ".join(group["NAME"])
	data = group["DATA"][0]
	mac = group["MAC"][0]
	entries.append(Entry(name, data, mac))

# aux functions

def ask_password(prompt = "passphrase", *, repeat = False):
	p = ""
	while not p:
		while not p:
			p = getpass(f"{prompt}: ")
			if not p.isascii():
				print("Invalid characters! (ASCII only)")
				p = ""
		if repeat:
			if p != getpass(f"repeat {prompt}: "):
				print("Input differs!")
				p = ""
	return p

def get_entry(i):
	i = int(i)
	if i < 1 or i > len(entries):
		print("No entry with this number!")
		return None
	return entries[i-1]

def add_entry(name, secret, password):
	e = Entry.from_secret(name, secret, password)
	entries.append(e)
	f.write(str(e))

# menu functions

def print_entries():
	for i, e in enumerate(entries, 1):
		print(f"{i})\t{e.name}")
	if entries:
		print()

def menu_add(name):
	if not name:
		print("Empty name!")
		return False
	secret = ask_password("secret")
	secret = bytes.fromhex(secret).hex().upper()
	password = ask_password(repeat = True)
	add_entry(name, secret, password)
	return True

def menu_add32(name):
	if not name:
		print("Empty name!")
		return False
	secret = ask_password("secret").upper()
	secret = b32decode(secret).hex().upper()
	password = ask_password(repeat = True)
	add_entry(name, secret, password)
	return True

def menu_totp(n, options):
	if not n.isdigit():
		print("N must be a number!")
		return True
	e = get_entry(n)
	if not e:
		return True
	password = ask_password()
	secret = e.get_secret(password)
	if secret is None:
		print("Invalid password or corrupted entry!")
	else:
		ans = secret.totp(options)
		print(ans.strip())
	return False

# main loop

flag = True
while True:
	garbage_collect()
	if flag:
		print_entries()
		print("quit\t:\tterminate the program")
		print("list\t:\tlist entries and commands")
		print("add NAME\t:\tadd a new entry NAME for a secret encoded in hex")
		print("add32 NAME\t:\tadd a new entry NAME for a secret encoded in in base32")
		print("totp N [OPTIONS]\t:\tget a new totp code from entry number N (OPTIONS are passed to oathtool)")
		print()
		flag = False
	try:
		match input("> ").split():
			case ["add", *name]:
				name = " ".join(name)
				flag = menu_add(name)
			case ["add32", *name]:
				name = " ".join(name)
				flag = menu_add32(name)
			case ["totp", n, *options]:
				options = " ".join(options)
				flag = menu_totp(n, options)
			case ["list"]:
				flag = True
			case ["quit"]:
				f.close()
				exit(0)
			case _:
				print("Unknown command!")
				flag = True
	except Exception as e:
		print("An error has occurred!")
		print(e)
		flag = True
	print()
