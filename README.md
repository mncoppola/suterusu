Suterusu
========

Typical compilation steps:

    $ wget http://kernel.org/linux-x.x.x.tar.gz
    $ tar xvf linux-x.x.x.tar.gz
    $ cd linux-x.x.x
    $ make menuconfig
    $ make modules_prepare
    $ cd /path/to/suterusu
    $ make linux-x86 KDIR=/path/to/kernel


To compile against the currently running kernel (kernel headers installed):

    $ make linux-x86 KDIR=/lib/modules/$(uname -r)/build


If a specific toolchain is desired for cross-compilation, provide the
CROSS_COMPILE variable during make:

    $ make android-arm CROSS_COMPILE=arm-linux-androideabi- KDIR=/path/to/kernel


To compile the command binary:

    $ gcc sock.c -o sock


Commands
========

Root shell

    $ ./sock 0

Hide PID

    $ ./sock 1 [pid]

Unhide PID

    $ ./sock 2 [pid]

Hide TCPv4 port

    $ ./sock 3 [port]

Unhide TCPv4 port

    $ ./sock 4 [port]

Hide TCPv6 port

    $ ./sock 5 [port]

Unhide TCPv6 port

    $ ./sock 6 [port]

Hide UDPv4 port

    $ ./sock 7 [port]

Unhide UDPv4 port

    $ ./sock 8 [port]

Hide UDPv6 port

    $ ./sock 9 [port]

Unhide UDPv6 port

    $ ./sock 10 [port]

Hide file/directory

    $ ./sock 11 [name]

Unhide file/directory

    $ ./sock 12 [name]

Hide network PROMISC flag

    $ ./sock 13

Unhide network PROMISC flag

    $ ./sock 14

Enable module loading (force kernel.modules_disabled=0)

    $ ./sock 15

Silently prohibit module loading (neutralize future loaded modules)

    $ ./sock 16

Silently re-permit module loading (undo command 16)

    $ ./sock 17


File/directory hiding
---------------------

At the moment, file/dir hiding only hides names on the / filesystem.  Note that names are hidden, not paths.  For instance, giving the name ".blah" to Suterusu will hide the name ".blah" in all directories on the filesystem.
