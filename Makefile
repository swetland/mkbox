
all: mkbox

mkbox: mkbox.c
	$(CC) -Wall -O1 -g -o mkbox mkbox.c

clean:
	rm -f mkbox

test: mkbox
	mkdir -p sandbox databox sandbox/bin
	cp /bin/busybox sandbox/bin
	chmod 755 sandbox/bin/busybox
	( cd sandbox/bin && for x in $$(busybox --list) ; do ln -fs busybox $$x ; done )
	./mkbox sandbox `pwd`/databox

clean-test::
	rm -rf sandbox databox

