#!/usr/local/bin/perl

use strict;
use warnings;


my $UP = `tput up`;
my $DOWN = "\n";
my $CE = `tput ce`;

my $RE_IP = qr/(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[0-9])/;


$| = 1;
$SIG{__WARN__} = sub {};

my $curline = 0;
my @line = (
	{
		obj => line->new(prompt => " ?  : "),
	},
	{
		obj => line->new(prompt => "num : "),
		evaluate => sub {
			my ($ip, $mask) = eval_addr_mask(shift);
			sprintf("%s", "$ip");
		},
	},
	{
		obj => line->new(prompt => "hex : "),
		evaluate => sub {
			my ($ip, $mask) = eval_addr_mask(shift);
			my $hex = sprintf("%016x", $ip);
			$hex =~ s/(.{4})\B/${1}_/sg;
			my $str = sprintf("0x%08x", $ip);
			sprintf("%-24s # %s", $str, $hex);
		},
	},
	{
		obj => line->new(prompt => "oct : "),
		evaluate => sub {
			my ($ip, $mask) = eval_addr_mask(shift);
			my $oct = sprintf("%024o", $ip);
			$oct =~ s/(.{3})\B/${1}_/sg;
			my $str = sprintf("0%o", $ip);
			sprintf("%-24s # %s", $str, $oct);
		},
	},
	{
		obj => line->new(prompt => "bin : "),
		evaluate => sub {
			my ($ip, $mask) = eval_addr_mask(shift);
			my $bin = strbinary($ip);
			$bin = join("", reverse(split(//, $bin)));
			$bin =~ s/(.{8})\B/${1}_/sg;
			$bin = join("", reverse(split(//, $bin)));
			"0b" . $bin;
		},
	},

	{
		obj => line->new(prompt => "IP  : "),
		evaluate => sub {
			my ($ip, $mask) = eval_addr_mask(shift);
			num2ipaddr($ip);
		},
	},
	{
		obj => line->new(prompt => "mask: "),
		evaluate => sub {
			my ($ip, $mask) = eval_addr_mask(shift);
			num2ipaddr($mask);
		},
	},
	{
		obj => line->new(prompt => "From: "),
		evaluate => sub {
			my ($ip, $mask) = eval_addr_mask(shift);
			num2ipaddr($ip & $mask);
		},
	},
	{
		obj => line->new(prompt => "To  : "),
		evaluate => sub {
			my ($ip, $mask) = eval_addr_mask(shift);
			num2ipaddr(($ip & $mask) + ~$mask);
		},
	},
);


$SIG{INT} = sub{ print "\n" x (@line - $curline); exit };

if ($#ARGV >= 0) {
	$line[0]->{obj}->setbuffer(join(" ", @ARGV));
}



for (@line) {
	$_->{obj}->redraw();
	print "\n";
}
print $UP x @line;

while (1) {
	if ($curline == 0) {
		my $value = $line[$curline]->{obj}->buffer();
		for (1 .. $#line) {
			print $DOWN;
			$line[$_]->{obj}->setbuffer($line[$_]->{evaluate}->($value));
			$line[$_]->{obj}->redraw();
		}
		print $UP x (@line - 1);
		print "\r";
	}
	$line[$curline]->{obj}->redraw();

	my $char = getc;
	my $c = unpack("C", $char);

	if ($c == 0x0d || $c == 0x0a) {	# \r or \n
		my $buf = $line[$curline]->{obj}->buffer();
		$buf =~ s/\s*#.*//;
		$buf =~ s/_//sg;
		$line[0]->{obj}->setbuffer($buf);
		print $UP x $curline;
		$curline = 0;
	} elsif ($c == 0x03) {	# ^C
		last;
	} elsif ($c == 0x1a) {	# ^Z
		print $DOWN x ($#line - $curline);
		$line[0]->{obj}->suspend();

	} elsif ($c == 0x0e) {	# ^N
		if ($curline == $#line) {
			$curline = 0;
			print $UP x $#line;
		} else {
			$curline++;
			print $DOWN;
		}
	} elsif ($c == 0x10) {	# ^P
		if ($curline == 0) {
			$curline = $#line;
			print $DOWN x $#line;
		} else {
			$curline--;
			print $UP;
		}
	} else {
		$line[$curline]->{obj}->input($char);
	}
}

$line[0]->{obj}->deinitialize();
print $DOWN x ($#line - $curline), "\n";




sub eval_addr_mask {
	local $_ = shift;

	my ($ip, $mask);

	if (m,^$RE_IP$,) {
		$ip = ipaddr2num($_);
		$mask = 0xffffffff;
	} elsif (m,^$RE_IP/$RE_IP$,) {
		my ($_ip, $_mask) = split("/", $_, 2);
		$ip = ipaddr2num($_ip);
		$mask = ipaddr2num($_mask);
	} elsif (m,^$RE_IP/\d+$,) {
		my ($_ip, $prefix) = split("/", $_, 2);
		$ip = ipaddr2num($_ip);
		$mask = 0xffffffff << (32 - $prefix);
	} else {
		$ip = eval($_);
	}

	($ip, $mask);
}

sub num2ipaddr {
	my $n = shift;

	sprintf("%d.%d.%d.%d",
	    ($n >> 24) & 0xff,
	    ($n >> 16) & 0xff,
	    ($n >> 8) & 0xff,
	    $n & 0xff
	);
}

sub ipaddr2num {
	my $addr = shift;

	my @qd = split(/\./, $addr, 4);

	($qd[0] << 24) + ($qd[1] << 16) + ($qd[2] << 8) + $qd[3];
}

sub strbinary {
	my $n = shift;
	my $hex = sprintf("%08x", $n);
	my $result = '';
	my @bintbl = qw(0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111);
	for (split(//, $hex)) {
		$result .= $bintbl[hex($_)];
	}
	$result;
}

package line;
use strict;
use warnings;
use POSIX;
use Data::Dumper;

my $tty_setup_done;

# convenience function
sub in_multibyte {
	my $str = shift;
	my $nth = shift;

	unpack("C", substr($str, $nth, 1)) >= 0x80;
}

sub is_multibyteprefix {
	my $char = shift;

	($char >= 0x80)
}

sub is_controlcode {
	my $char = shift;

	($char < 0x20) || ($char == 0x7f);
}

sub new {
	my $class = shift;
	my $self = {};
	bless $self;
	$self->initialize();

	my %arg = @_;
	while (my ($key, $val) = each %arg) {
		($key eq 'prompt') && do {
			$self->setprompt($val);
		};
	}


	$self;
}

sub destroy {
	my $self = shift;
	$self->deinitialize();
}

sub initialize {
	my $self = shift;

	$self->{'killbuffer'} = '';
	$self->{'prompt'} = '>';
	$self->reset();
	$self->ttysetup();
}

sub ttysetup {
	my $self = shift;
	unless ($tty_setup_done) {
		chop($self->{'stty'} = `stty -g`);
		`stty raw -echo`;
		$self->{CE} = `tput ce`;
	}
}

sub ttyrestore {
	my $self = shift;
	my $stty = $self->{'stty'};
	delete $self->{'stty'};
	system("stty $stty");
}

sub deinitialize {
	my $self = shift;
	$self->ttyrestore();
}

sub reset {
	my $self = shift;
	$self->{'linebuffer'} = '';
	$self->{'position'} = 0;
	$self->{'escape'} = 0;
	$self->{'ctrlx'} = 0;
	$self->{'validmark'} = 0;
	$self->{'mark'} = 0;
	$self->{'mb1st'} = '';
	$self->{'doprompt'} = 1;

	undef $self->{'prefix'};
}

sub buffer {
	my $self = shift;
	$self->{'linebuffer'};
}

sub setbuffer {
	my $self = shift;
	$self->reset();
	$self->{'linebuffer'} = shift;
	$self->{'position'} = length($self->{'linebuffer'});
}

sub prompt {
	my $self = shift;
	if ($self->{'doprompt'}) {
		print $self->{'prompt'};
		$self->{'doprompt'} = 0;
	}
}

sub setprompt {
	my ($self, $prompt) = @_;
	$self->{'prompt'} = $prompt;
}

sub beep {
	print "\x7";
}

sub setmark {
	my $self = shift;
	$self->{'validmark'} = 1;
	$self->{'mark'} = $self->{'position'};
}

sub getmark {
	my $self = shift;

	unless ($self->{'validmark'}) {
		return undef
	}

	if ($self->{'mark'} < 0) {
		return 0;
	}

	if ($self->{'mark'} > length($self->{'linebuffer'})) {
		return length($self->{'linebuffer'});
	}

	$self->{'mark'};
}

sub swapmark {
	my $self = shift;
	my $oldmark = $self->getmark();

	unless (defined($oldmark)) {
		return undef;
	}

	$self->setmark();

	if ($self->{'position'} < $oldmark) {
		while ($self->{'position'} != $oldmark) {
			$self->forward(1);
		}
	} else {
		while ($self->{'position'} != $oldmark) {
			$self->backward(1);
		}
	}
}


sub killregion {
	my $self = shift;

	unless (defined($self->getmark())) {
		return undef;
	}

	$self->clearkillbuffer();

	if ($self->{'position'} > $self->getmark()) {
		$self->swapmark();
	}

	while ($self->{'position'} != $self->getmark()) {
		$self->delete(1, 1);
	}
}

sub clearkillbuffer {
	my $self = shift;
	$self->{'killbuffer'} = '';
}

sub insert {
	my $self = shift;
	my $str = shift;

	substr($self->{'linebuffer'}, $self->{'position'}, 0) = $str;
	print substr($self->{'linebuffer'}, $self->{'position'});
	print "\b" x (length(substr($self->{'linebuffer'}, $self->{'position'})) - length($str));

	$self->{'position'} += length($str);
	if ($self->{'mark'} > $self->{'position'}) {
		$self->{'mark'} += length($str);
	}
}

sub delete {
	my ($self, $num, $appendtokill) = @_;
	my ($killbuffer, $ch);

	return undef if ($self->{'position'} >= length($self->{'linebuffer'}));

	for (1 .. $num) {
		last if ($self->{'position'} >= length($self->{'linebuffer'}));

		if (in_multibyte($self->{'linebuffer'}, $self->{'position'})) {
			$ch = substr($self->{'linebuffer'}, $self->{'position'}, 2);
			substr($self->{'linebuffer'}, $self->{'position'}, 2) = '';
		} else {
			$ch = substr($self->{'linebuffer'}, $self->{'position'}, 1);
			substr($self->{'linebuffer'}, $self->{'position'}, 1) = '';
		}
		$killbuffer .= $ch;
	}

	if ($appendtokill) {
		$self->{'killbuffer'} .= $killbuffer;
	}

	if ($self->{'position'} < $self->{'mark'}) {
		$self->{'mark'} -= length($killbuffer);
	}

	print substr($self->{'linebuffer'}, $self->{'position'});
	print " " x length($killbuffer);
	print "\b" x (length($killbuffer) + length($self->{'linebuffer'}) - $self->{'position'});
}

sub backspace {
	my ($self, $num, $appendtokill) = @_;

	if ($self->backward($num)) {
		$self->delete($num, $appendtokill);
	}
}

sub backward {
	my $self = shift;
	my $num = shift;

	if ($num == 1) {
		return undef if ($self->{'position'} == 0);

		$self->{'position'}--;
		if ($self->{'position'} && in_multibyte($self->{'linebuffer'}, $self->{'position'})) {
			$self->{'position'}--;
			print "\b\b";
		} else {
			print "\b";
		}
		1;
	} else {
		if ($num >= length($self->{'linebuffer'})) {
			$num = length($self->{'linebuffer'});
		}
		for (1 .. $num) {
			$self->backward(1) or last;
		}
		1;
	}
}

sub forward {
	my $self = shift;
	my $num = shift;

	if ($num == 1) {
		my $len = length($self->{'linebuffer'});
		my $pos = $self->{'position'};

		return undef if ($pos >= $len);

		if ((($len - $pos) >= 2) && in_multibyte($self->{'linebuffer'}, $pos)) {
			print substr($self->{'linebuffer'}, $pos, 2);
			$self->{'position'} += 2;
		} else {
			print substr($self->{'linebuffer'}, $pos, 1);
			$self->{'position'}++;
		}
		1;
	} else {
		if ($num >= length($self->{'linebuffer'})) {
			$num = length($self->{'linebuffer'});
		}
		for (1 .. $num) {
			$self->forward(1) or last;
		}
		1;
	}
}

sub inword {
	my $self = shift;
	substr($self->{'linebuffer'}, $self->{'position'}, 1) =~ m/[\w\x80-\xff]/;
}

sub forward_word {
	my ($self, $num) = @_;

	if ($num >= length($self->{'linebuffer'})) {
		$num = length($self->{'linebuffer'});
	}

	for (1 .. $num) {
		while (!$self->inword()) {
			$self->forward(1) or return;
		}
		while ($self->inword()) {
			$self->forward(1) or return;
		}
	}
}

sub backward_word {
	my ($self, $num) = @_;

	if ($num >= length($self->{'linebuffer'})) {
		$num = length($self->{'linebuffer'});
	}

	for (1 .. $num) {
		do {
			$self->backward(1) or return;
		} while (!$self->inword());
		do {
			$self->backward(1) or return;
		} while ($self->inword());
		$self->forward(1);
	}
}

sub delete_word {
	my ($self, $num) = @_;

	$self->clearkillbuffer();

	if ($num >= length($self->{'linebuffer'})) {
		$num = length($self->{'linebuffer'});
	}
	for (1 .. $num) {
		while (!$self->inword()) {
			$self->delete(1, 1) or return;
		}
		while ($self->inword()) {
			$self->delete(1, 1) or return;
		}
	}
}

sub backdelete_word {
	my ($self, $num) = @_;

	$self->clearkillbuffer();

	$self->backward_word($num);
	$self->delete_word($num);
}

sub beginning_of_line {
	my $self = shift;
	$self->backward(length($self->{'linebuffer'}));
}

sub end_of_line {
	my $self = shift;
	$self->forward(length($self->{'linebuffer'}));
}

sub killline {
	my $self = shift;
	$self->beginning_of_line();

	$self->clearkillbuffer();

	$self->delete(length($self->{'linebuffer'}), 1);
}

sub killtoend {
	my $self = shift;

	$self->clearkillbuffer();

	$self->delete(length($self->{'linebuffer'}) - $self->{'position'}, 1);
}

sub yank {
	my $self = shift;
	$self->setmark();
	$self->insert($self->{'killbuffer'});
}

sub save {
	my $self = shift;

	my $r = length($self->{'linebuffer'}) - $self->{'position'};
	print " " x $r;
	print "\b" x $r;
	print "\b \b" x (length($self->{'prompt'}) + $self->{'position'});
}

sub restore {
	my $self = shift;

	print $self->{'prompt'};
	print $self->{'linebuffer'};
	print $self->{CE};
	print "\b" x (length($self->{'linebuffer'}) - $self->{'position'});

	$tty_setup_done = 0;
}

sub redraw {
	my $self = shift;

	print "\r";
	$self->restore();
	$self->{'doprompt'} = 0;
}

sub clear {
	my $self = shift;

	# nothing
}


sub suspend {
	my $self = shift;

	$self->ttyrestore();
	print "\n";

	kill SIGTSTP, 0;

	$self->ttysetup();
	$self->restore();
}


sub input {
	my $self = shift;
	my $char = shift;

	my $code = unpack("C", $char);

	if ($self->{'doprompt'}) {
		print $self->{'prompt'};
		$self->{'doprompt'} = 0;
	}

	if (($self->{'escape'} || defined($self->{'prefix'})) &&
	    ($char =~ m/\d/)) {

		$self->{'prefix'} = $self->{'prefix'} * 10 + $char;
		$self->{'escape'} = 0;

	} elsif ($self->{'escape'}) {
		SWITCH: {
			(0x08 == $code) && do {    # M-^H
				if ($self->{'prefix'}) {
					$self->backdelete_word($self->{'prefix'});
				} else {
					$self->backdelete_word(1);
				}
				last SWITCH;
			};
			('b' eq $char) && do {     # M-b
				if ($self->{'prefix'}) {
					$self->backward_word($self->{'prefix'});
				} else {
					$self->backward_word(1);
				}
				last SWITCH;
			};
			('d' eq $char) && do {     # M-d
				if ($self->{'prefix'}) {
					$self->delete_word($self->{'prefix'});
				} else {
					$self->delete_word(1);
				}
				last SWITCH;
			};
			('f' eq $char) && do {     # M-f
				if ($self->{'prefix'}) {
					$self->forward_word($self->{'prefix'});
				} else {
					$self->forward_word(1);
				}
				last SWITCH;
			};

			# default
			beep();
		}
		$self->{'escape'} = 0;
		undef $self->{'prefix'};

	} elsif ($self->{'ctrlx'}) {
		SWITCH: {
			(0x18 == $code) && do {    # ^X^X
				$self->swapmark();
				last SWITCH;
			};
			beep();
		}
		$self->{'ctrlx'} = 0;
		undef $self->{'prefix'};

	} else {
		if (0x1b == $code) {               # ESC

			$self->{'escape'} = 1;

		} else {
			SWITCH: {
				(0x00 == $code) && do {    # ^@
					$self->setmark();
					last SWITCH;
				};
				(0x01 == $code) && do {    # ^A
					$self->beginning_of_line();
					last SWITCH;
				};
				(0x02 == $code) && do {    # ^B
					if ($self->{'prefix'}) {
						$self->backward($self->{'prefix'});
					} else {
						$self->backward(1);
					}
					last SWITCH;
				};
				(0x04 == $code) && do {    # ^D
					if ($self->{'linebuffer'} eq '') {
						print "^D\r\n";
						$self->reset();
						return '';
					}

					if ($self->{'prefix'}) {
						$self->delete($self->{'prefix'}, 0);
					} else {
						$self->delete(1, 0);
					}
					last SWITCH;
				};
				(0x05 == $code) && do {    # ^E
					$self->end_of_line();
					last SWITCH;
				};
				(0x06 == $code) && do {    # ^F
					if ($self->{'prefix'}) {
						$self->forward($self->{'prefix'});
					} else {
						$self->forward(1);
					}
					last SWITCH;
				};
				((0x08 == $code) || (0x7f == $code)) && do {    # ^H
					if ($self->{'prefix'}) {
						$self->backspace($self->{'prefix'}, 0);
					} else {
						$self->backspace(1, 0);
					}
					last SWITCH;
				};
				(0x0b == $code) && do {    # ^K
					$self->killtoend();
					last SWITCH;
				};
				(0x0c == $code) && do {    # ^L
					$self->clear();
					last SWITCH;
				};
				(0x12 == $code) && do {    # ^R
					$self->redraw();
					last SWITCH;
				};
				(0x15 == $code) && do {    # ^U
					$self->killline();
					last SWITCH;
				};
				(0x17 == $code) && do {    # ^W
					$self->killregion();
					last SWITCH;
				};
				(0x18 == $code) && do {    # ^X
					$self->{'ctrlx'} = 1;
					last SWITCH;
				};
				(0x19 == $code) && do {    # ^Y
					$self->yank();
					last SWITCH;
				};
				(0x1a == $code) && do {    # ^Z
					$self->suspend();
					last SWITCH;
				};

				((0x0a == $code) || (0x0d == $code)) && do {    # \r or \n
					print "\r\n";
					$_ = $self->{'linebuffer'};
					$self->reset();
					return $_;
				};

				if (is_controlcode($code)) {
					beep();
				} elsif (!is_multibyteprefix($code)) {
					$self->insert($char);
				} else {
					if ($self->{'mb1st'} ne '') {
						$self->insert($self->{'mb1st'}.$char);
						$self->{'mb1st'} = '';
					} else {
						$self->{'mb1st'} = $char;
					}
				}
			}

			undef $self->{'prefix'};
		}
	}

undef;
}
