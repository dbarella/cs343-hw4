'''
Script by Dan Bee, Laura Watiker, Paul Jones

Usage: python analysis.py <tcpdump.pcap_file> (AKA the file that tcpdump writes when you use the -w flag)
'''

import subprocess as s
import sys

DEFAULT_TIMEOUT = 200

SYN = 'syn'
SYN_ACK = 'syn-ack'
ACK = 'ack'
RESET = 'reset'
FIN = 'fin'
FIN_ACK = 'fin-ack'

class Packet(object):
	'''
	Represents a TCP packet object
	'''

	def __init__(self, input_string):
		'''
		Packets are initialized from tcpdump's output to stdout. Janky and all but HEYOOOOOOO.
		'''
		arr = input_string.split()
		self.data = tuple(arr) #This is not really for anyone to use - it just lets us generate a uniqe hash output

		#Make timestamp into a float
		a = map(float, arr[0].split(':'))
		self.time = sum((a[0]*60*60, a[1]*60, a[2]))
		self.src = arr[2]
		self.dst = arr[4]

		#Set this packet's type
		typ = arr[6].rstrip(',')
		if typ == '[S]':
			self.typ = SYN
		elif typ == '[S.]':
			self.typ = SYN_ACK
		elif typ in ['[R]', '[R.]']:
			self.typ = RESET
		elif typ == '[F]':
			self.typ = FIN
		elif typ == '[F.]':
			self.typ = FIN_ACK
		else:
			self.typ = ACK

	def connection_id(self):
		return '{0} > {1}'.format(self.src, self.dst)

	def __repr__(self):
		return '{0}: {1} > {2} [{3}]'.format(self.time, self.src, self.dst, self.typ)

	def __hash__(self):
		return hash(self.src + self.dst)

	def __eq__(self, other):
		return self.src == other.src and self.dst == other.dst

def gen_packet_list(filename):
	p = s.Popen(('tcpdump', '-r', filename, 'tcp[tcpflags] & (tcp-ack|tcp-syn|tcp-rst|tcp-fin) != 0'), stdout=s.PIPE)
	
	packets = []
	try: 
		for row in p.stdout:
			packet = Packet(row)
			packets.append(packet)
	except KeyboardInterrupt:
		p.terminate()

	return packets

def main():
	if len(sys.argv) != 2:
		print 'Usage: python analysis.py <tcpdump.pcap_file>'
		sys.exit(1)

	packets = gen_packet_list(sys.argv[1])

	syn_to_fin_ack = {}
	for packet in packets:
		if packet.typ == SYN:
			syn_to_fin_ack[packet] = None
		elif packet in syn_to_fin_ack and packet.typ == FIN_ACK:
			syn_to_fin_ack[packet] = packet

	computed_times = []
	for syn, fin_ack in syn_to_fin_ack.items():
		if fin_ack is not None:
			computed_times.append((syn.connection_id(), fin_ack.time - syn.time))
		else:
			computed_times.append((syn.connection_id(), DEFAULT_TIMEOUT))

	for ident, time in computed_times:
		print ident, time
	
if __name__ == '__main__':
	main()
