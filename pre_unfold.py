import sys

def pre_unfold(fileName,outputFileName):
	with open(fileName,'r') as inputFile:
		with open(outputFileName,'w') as outputFile:
			for line in inputFile:
				line = line.strip()
				if line[0] == '[':
					wireName=line.split(' ')[1]
					maxIndex,minIndex=line.split(' ')[0][1:-1].split(':')
					maxIndex,minIndex=int(maxIndex),int(minIndex)
					while minIndex<=maxIndex:
						outputFile.write(wireName+'['+str(minIndex)+']\n')
						minIndex+=1
				else:
					outputFile.write(line+'\n')
			#outputFile.write(sys.argv[1]+' '+sys.argv[2])

if __name__ == '__main__':
	pre_unfold(sys.argv[1],sys.argv[2])