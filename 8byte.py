from capstone import *

def sub_4015e0(b ,arg):
	v1 = arg & 0 # zero it
	v2 = b >> v1
	v3 = -(v1) 
	v3 = v3 & 0 # zero it
	v4 = b << v3
	return v2 | v4

def sub_4015A0(b ,arg):
	v1 = arg & 0 
	v2 = b << v1
	v3 = -(v1) 
	v3 = v3 & 0
	v4 = b >> v3
	return v2 | v4

def sub_401760(b):
	arg1 = b ^ 0x35
	second_args = [0x7,0x5,0x5]
	v1 = sub_4015e0(arg1, second_args[0])
	arg1 = v1 - 0xA
	v2 = sub_4015A0(arg1, second_args[1])
	arg1 = v2 - 0x2
	v3 = sub_4015e0(arg1, second_args[2])
	return v3

def sub_401840(b):
	second_args = [0xD, 0x12,0xE,0x1,0x1F]
	arg1 = b ^ 0xAA
	v1 = sub_4015e0(arg1, second_args[-1])
	arg1 = v1 + 0x6
	v2 = sub_4015A0(arg1, second_args[-2])
	arg1 = v2 + 0x9
	v3 = sub_4015e0(arg1, second_args[-3])
	v4 = sub_4015A0(v3,second_args[-4])
	arg1 = v4 - 0x6
	v5 = sub_4015A0(arg1,second_args[-5])
	return v5+0xC

def sub_4017E0(b):
	second_args=[0xA,0x5,0xA,0x5,0x4]
	arg1 = b ^ 0x75
	v1 = sub_4015A0(arg1,second_args[-1])
	arg1 = v1 + 0x2
	v2 = sub_4015A0(arg1,second_args[-2])
	arg1 = v2 + 0xA
	v3 = sub_4015A0(arg1,second_args[-3])
	v3 = sub_4015e0(v3,second_args[-4])
	arg1 = v3 - 0x5
	v4 = sub_4015A0(arg1,second_args[-5])
	return v4 + 0x5

def sub_4017A0(b):
	second_args=[0x3d,0x5,0x4]
	v1 = sub_4015A0(b, second_args[-1])
	arg1 = v1 - 0x14
	v2 = sub_4015e0(arg1, second_args[-2])
	arg1 = v2 - 0xD
	v3 = sub_4015e0(arg1, second_args[-3])
	return v3 ^ 0xCA

def loc_40210E(b):
	r1 = sub_401760(b) & 0xff
	#print(hex(r1))
	r2 = sub_401840(r1-0xD) & 0xff
	r3 = sub_4017E0(r2+0x3) & 0xff
	#print(hex(r3))
	r4 = sub_401760(r3-0x15) & 0xff
	#print(hex(r4))
	r5 = sub_401840(r4+0xf) & 0xff
	#print(hex(r5))
	r6 = sub_4017A0(r5-0x14) & 0xff
	#print(hex(r6))
	r7 = sub_4017A0(r6+0xD) & 0xff
	#print(hex(r6))
	r8 = sub_401760(r7-0xC) & 0xff
	#print(hex(r8))
	return r8


if __name__ == "__main__":
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	#opcode = b'\xCC\x37\x13\x92\xA3\x37\x13\x2A\xA3\x43\x37\x13\x76\x0C\xAB\x68\xE7\x27\x37\x13\x80\xBB\x27\x27\x27\x37\x13\xE8\x08\x27\x37\x13'
	bytecode=b""
	with open('C:\\Users\\ilovecookies\\Desktop\\binary.exe', 'rb') as f:
		f.seek(0x4800)
		bytecode = f.read(0xc087-0x8000)

	#print(bytecode)
	program=[]
	dis=bytearray()
	while(len(bytecode)):
		if len(bytecode) >= 2 and bytecode[0] == 0x37 and bytecode[1] == 0x13:
			bytecode = bytecode[2:]
			program.append(dis)
			dis = bytearray()
		else:
			# print(hex(loc_40210E(b1)))
			# print(hex(loc_40210Eb2)))
			dis.append(loc_40210E(bytecode[0]))
			bytecode = bytecode[1:]

	# output a new bin file
	f = open('C:\\Users\\ilovecookies\\Desktop\\get_flag','wb')
	for inst in program:
		f.write(inst)
		# for i in md.disasm(inst,0x407001):
		# 			print("{}\t{}".format(i.mnemonic,i.op_str))
		# 			asm.append("{}\t{}".format(i.mnemonic,i.op_str))
	f.close()
