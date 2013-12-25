#!/usr/bin/python

import sys
import os

argv = sys.argv
argc = len(argv)

if argc != 3:
	print "Usage: " + argv[0] + " porgramme-name start-cpu-to-bind."
	exit(1)

pro_name = argv[1]
cpu_start = int(argv[2])

pros = os.popen("pgrep " + pro_name).readlines()

for pid in pros:
	os.system("taskset -pc " + str(cpu_start) + " " + pid)
	cpu_start += 1





