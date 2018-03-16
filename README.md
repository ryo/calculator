# interactive dec/hex/oct/bin and IPv4 address calculator with emacs like bindings.

	% c
	 ?  : 172.18.19.20/21
	num : 2886865684
	hex : 0xac121314               # 0000_0000_ac12_1314
	oct : 025404411424             # 000_000_000_000_025_404_411_424
	bin : 0b10101100_00010010_00010011_00010100
	IP  : 172.18.19.20
	mask: 255.255.248.0
	From: 172.18.16.0
	To  : 172.18.23.255

	% c
	 ?  : 0xdeadbeaf+559038800
	num : 4294967295
	hex : 0xffffffff               # 0000_0000_ffff_ffff
	oct : 037777777777             # 000_000_000_000_037_777_777_777
	bin : 0b11111111_11111111_11111111_11111111
	IP  : 255.255.255.255
	mask: 0.0.0.0
	From: 0.0.0.0
	To  : 0.0.0.0


## notice
this is implemented with perl ''eval'' op. be careful to input/paste illegal data.
