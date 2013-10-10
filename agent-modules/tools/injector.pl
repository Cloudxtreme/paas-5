#!/usr/bin/perl
# vim: set ts=4 sw=4:
#Copyright (c) 2010  Sinobot, Inc.
# Author: Jiff Shen <m3l3m01t@gmail.com>
#

use diagnostics;
use warnings; 
use sigtrap;
use strict;
use Getopt::Long;
use File::Temp;
use English; # for descriptive predefined var names, such as:
use Switch;

sub vrun(@) {
	my @cmd = @_;
	system (@cmd);
	my $ret = $?;	
	if ($ret == -1) {
		print (STDERR "failed to vrun $cmd[0]\n");
		return -1;
	}
	elsif ( $ret & 127) {
		printf STDERR "%s died with signal: %d\n", $cmd[0], ($ret & 127);
		return -1;
	} 

	$ret = ($ret >> 8);
	if ( $ret != 0) {
		printf STDERR "%s returned: %d\n",$cmd[0], $ret;
	}
	return $ret;
}

delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
$ENV{'PATH'}='/bin:/usr/bin:/sbin:/usr/sbin/:/usr/local/sbin:/usr/local/bin';


my $ret = 1;
#
# 	injector.pl [ -d|--dir directory ] [ -i|--image winxp.qcow2 ] [ -n|--nbd nbd_number ]
#				[ -p|--prefix='HKEY_LOCAL_MACHINE\System' -r|--regfile=registry_file ]
#				[[file] [srcfile=destfile] [file] ...]
#

# process command-line parameters
my %opts = ();
GetOptions(\%opts, 'dir|d=s', 'image|i=s', 'nbd|n=i', 'prefix|p=s@',
	'regfile|r=s@') or die "Unknown parameter: $!\n";

my %files;
foreach (@ARGV) {
	my ($src, $dst) = split (/=/, $_);
	$files{$src} = $dst ? $dst : "";
	if ( not (-f $src  and -r $src)) {
		print STDERR "cannot read $src\n";
		goto CLEAN;
	}
}

#
#printf STDOUT "ARGV[%d]: @ARGV\n", scalar(@ARGV);
#foreach (keys %files) {
#   #### handle the case item was not initialized
#	if ($files{$_}) {
#		print "$_ = $files{$_}\n";
#	} else {
#		print "$_ = \"\"\n";
#	}
#}
#

if (not (exists $opts{'dir'} or exists $opts{'image'})) {
	# neither src directory nor image was specified, where is the dest?
	print STDERR "either --dir or --image must be specified\n";
	goto CLEAN;
}

my %regs;
if ( exists $opts{'regfile'} ) {
	if (not exists $opts{'prefix'}) {
		print STDERR "prefix must specified for each registry file\n";
		goto CLEAN;
	}
	if ( scalar (@{$opts{'regfile'}}) != scalar (@{$opts{'prefix'}})) {
		print STDERR "--prefix and --regfile must be used as pair\n";
		goto CLEAN;
	}
	
	@regs{@{$opts{'regfile'}}} = @{$opts{'prefix'}};

	foreach my $key (keys %regs) {
		if ( not -r $key ) {
			print STDERR "cannot read regfile $key\n";
			goto CLEAN;
		}
		my @prefix = split(/\\/, $regs{$key});
		if (scalar(@prefix) != 2) {
			print STDERR "invalid prefix $prefix[0]\n";
			goto CLEAN;
		}
		switch ($prefix[0]) {
			case "HKEY_LOCAL_MACHINE" { }
			else 					  { print "unknown $prefix[0]\n"; goto CLEAN}
		}

		$prefix[1] = uc ($prefix[1]);
		switch ($prefix[1]) {
			case "SYSTEM"   {}
			case "SOFTWARE" {}
			case "SECURITY" {}
			case "DEFAULT"  {}
			case "COMPONENTS" {}
			case "SAM"        {}
			else   { print "unknown $prefix[1]\n"; goto CLEAN}
		}
		$regs{$key} = \@prefix;
	}

#
# #######  following code is to access array reference ######
#	foreach (keys %regs) {
#		my $ref = $regs{$_};
#		print "$_ --- @{$ref}\n";
#	}
# ##########################################################
#

}


if (not exists $opts{'dir'}) {
	$opts{'dir'} = mkdtemp ("/tmp/.euca-XXXXXX");
	$opts{'rmdir'} = 1;
}

(-d $opts{'dir'}) or goto CLEAN;

### if image is specified, mount it ####
if (exists $opts{'image'}) {
	my $begin;
	my $end;
	my $index;
	
	#if --nbd was not specified, we try to find one, else use the one specified
	if (exists $opts{'nbd'}) {
		$begin = $opts{'nbd'};
		$end = $opts{'nbd'};
	} else {
		$begin = 0;
		$end = 15;
	}
	delete $opts{'nbd'};

	for ( $index = $begin; $index <= $end; $index++) {
		my $fn;

		# see if this nbd device is being attached by read the 'size'
		$fn = sprintf ('/sys/dev/block/43:%d/size', $index * 16);
		open (my $fh, "<", "$fn")  or last;
		while (<$fh>){
			chomp;
			if ( $_ eq "0") {
				$opts{'nbd'} = "/dev/nbd$index";
				last;
			} else {
				print STDERR "info: /dev/nbd$index in use\n";
			}
		}
		close $fh;
		last if exists $opts{'nbd'};
	}
	if (not exists $opts{'nbd'}) {
		print (STDERR "no nbd device available\n");
		goto CLEAN;
	}

# attach with qemu-nbd
	if (vrun (("qemu-nbd", "-c", $opts{'nbd'}, $opts{'image'} ))== 0) {
		$opts{'detach'} = 1;
	} else {
		goto CLEAN;
	}

# waiting for udev to mknod for attached image
	for ($index = 0; $index < 4; $index++) {
		sleep (1);
		last if ( -e "$opts{'nbd'}p1");
	}

# assume system is on partition 1 ..... 
	if (vrun (("mount","$opts{'nbd'}p1", $opts{'dir'})) != 0) {
		goto CLEAN;
	}
	$opts{'umount'} = 1;
}
# for ntfs, you must install ntfs-3g + fuse package, or the fs will be mounted readonly.
if ( not -w $opts{'dir'} ) {
	print (STDERR "filesystem readonly:$opts{'dir'}");
	goto CLEAN;
}

# copy files to destination
foreach (keys %files) {
	vrun (("install", "-D", "$_", "$opts{dir}/$files{$_}"));
}

foreach my $regfile (keys %regs) {
	my $ref = $regs{$regfile};
	my ($hkey, $name) = @{$ref};
	next if ($hkey ne "HKEY_LOCAL_MACHINE");

	my $hive = "windows/system??/config/$name";
	my @array = split (/\//, $hive);
	my $depth = scalar (@array);

	$hive = "$opts{dir}/$hive";

	my $fh;

#	print STDERR "running: find $opts{dir} -maxdepth $depth  -mindepth $depth -iwholename $hive\n";
	open ($fh, "find $opts{dir} -maxdepth $depth  -mindepth $depth -iwholename \'$hive\' -iregex '.+/system\\(32\\|64\\)/config/\\w+' |");
	if ( $? != 0) {
		print STDERR "cannot find hive\n";
		goto CLEAN;
	}

	$hive = <$fh>;
	close $fh;
	chomp ($hive);
	if ( not $hive ) {
		print STDERR "hive $name not found\n";
		goto CLEAN;
	}
	if ( not -w $hive) {
		print STDERR "cannot write  to hive $hive\n";
		goto CLEAN;
	}
	
	if (vrun (("hivexregedit","--merge","--prefix", "$hkey\\$name", $hive, $regfile)) != 0) {
		print STDERR " cannot merge to hive $hive\n";
		goto CLEAN;
	}
}

$ret = 0;

CLEAN: 
if ( exists $opts{'umount'} ) {
	system ("umount $opts{'dir'}");
}
if ( exists $opts{'rmdir'} ) {
	rmdir ($opts{'dir'});
}
if ( exists $opts{'detach'} ) {
	system ("qemu-nbd -d $opts{'nbd'}");
}

exit $ret;
