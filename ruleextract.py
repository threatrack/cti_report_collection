import threatrack_iocextract
import sys

if __name__=="__main__":
	text = open(sys.argv[1],mode='r',encoding='utf-8').read()
	if sys.argv[2] in {'hostname','url','ipv4','email'}:
		# de-defang for specific iocs
		text = threatrack_iocextract.refang(text)

	iocs = threatrack_iocextract.extract(text,iocs=[sys.argv[2]])
	iocs = threatrack_iocextract.whitelist(iocs)
	print("\n".join(iocs[sys.argv[2]]))

