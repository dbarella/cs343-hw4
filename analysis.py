'''
Script by Dan Bee, Laura Watiker, Paul Jones

Usage: python analysis.py <tcpdump.pcap_file> (AKA the file that tcpdump writes when you use the -w flag)
'''

import subprocess as s
import sys

SYN = 'syn'
SYN_ACK = 'syn-ack'
ACK = 'ack'
RESET = 'reset'
FIN = 'fin'
FIN_ACK = 'fin-ack'

class Packet(object):
	def __init__(self, arr):
		self.data = tuple(arr)

		a = map(float, arr[0].split(':'))
		self.time = sum((a[0]*60*60, a[1]*60, a[2]))
		self.src = arr[2]
		self.dst = arr[4]

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

	def __repr__(self):
		return '{0}: {1} > {2} [{3}]'.format(self.time, self.src, self.dst, self.typ)

	def __hash__(self):
		return hash(self.data)

	def __eq__(self, other):
		return self.data == other.data

def main():
	if len(sys.argv) != 2:
		print 'Usage: python analysis.py <tcpdump.pcap_file>'
		sys.exit(1)

	p = s.Popen(('tcpdump', '-r', sys.argv[1], 'tcp[tcpflags] & (tcp-ack|tcp-syn|tcp-rst|tcp-fin) != 0'), stdout=s.PIPE)

	packets = dict()
	try: 
		for row in p.stdout:
			#print row.split()
			packet = Packet(row.split())
			packets[packet] = packet.time
	except KeyboardInterrupt:
		p.terminate()



	for key, val in packets.items():
		print key, val
	
if __name__ == '__main__':
	main()
