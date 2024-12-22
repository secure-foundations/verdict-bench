from subprocess import Popen, PIPE

argument = b'\x20\xEF\xB7\x90\x41\x42\x20'
stringprep = Popen(["./runStringPrep", argument], stdout=PIPE)
(output, err) = stringprep.communicate()
print(output)

for i in output:
	print(i)
