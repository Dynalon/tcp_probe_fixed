### __UNMAINTED WARNING__: I am not actively maintaining this module anymore. This code was designed to run against Ubuntu 12.04 kernel versions and I keep this repo for reference and historical reasons. I am not accepting pull requests and will not answer support inquiries sent to my private email.

About
======

This is my fixed version of the `tcp_probe.c` kernel module for linux. The version
that ships with the vanilla kernel was not suitable for me as it only writes to
/proc/net/tcpprobe in large buffer bursts, whereas I needed to monitor short
lived HTTP connections.

This version uses and `EVENT_BUF` value of 1 by default, which means every event
is written to /proc/net/tcpprobe immediately. An event can be either the
reception of a tcp segment of an established connection, or the _change_ of the
`snd_cwnd` (depending on whether or not the `full` module parameter is given).

Additionally, the timestamp is reset on every `fopen` of the
`/proc/net/tcp_probe` file for easier plotting.

For more information and documentation on original `tcp_probe`, see:

	<http://www.linuxfoundation.org/collaborate/workgroups/networking/tcpprobe>

The `sample_plot` folder contains a sample gnuplot plus two samples collected
via this kernel modules that show congestion behaviour using `tcp reno` and
linux' `tcp_cubic`.


Install & Usage
===============

Get and install matching linux-header package for your kernel and run `make`.

Usage: Same as the original `tcp_probe` module. I.e:

	insmod tcp_probe_fixed.ko port=8080 full=1

