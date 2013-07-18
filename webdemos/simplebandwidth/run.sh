#!/bin/bash
name="Simple Bandwidth"
dir="webdemos/simplebandwidth"
webport="8080"
dev=$1

cd ../../
pwd 

if [ ! -f "./mimir" ]; then
	echo "The mimir program must be in the current directory"
	exit
fi

if [ ! -d "./$dir" ]; then
	echo "I cannot find the $name directory at $dir"
	exit
fi

if [ "$dev" == "" ]; then
	echo "I need a device to listen on"
	exit
fi

./mimir -web-enable -web-port=$webport -web-root=$dir -d=$dev -web-debug
