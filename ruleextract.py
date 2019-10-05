import threatrack_iocextract
import sys

if __name__=="__main__":
	iocs = threatrack_iocextract.extract( open(sys.argv[1],'r').read() )
	print("\n".join(iocs[sys.argv[2]]))

