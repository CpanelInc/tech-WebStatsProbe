#!/usr/bin/perl

use warnings;
use strict;
use Term::ANSIColor qw(:constants);
#$Term::ANSIColor::AUTORESET = 1;

# cPanel, Inc.
# by: Paul Trost

my $version = 0.1;

# Set defaults for positional parameters
my $noquery = 1; # Default to doing DNS queries on user domains
my $user = "";

# Parse positional parameters for flags and set variables if argument is present
foreach( @ARGV ) {
	# if any of the arguments don't contain "--" then make that argument the user variable
	if ( $_ !~ '--' ) {
		$user = $_;
	}

	# noquery is used to turning off DNS lookups for user domains when webstatsprobe called against a user
	if ( $_ =~ '--noquery' ) {
		$noquery = 0;
	}
}


#############
## Functions #
##############
sub BlackedHours {
# Get the blackout hours and display if stats can run within those hours
	if ( -f '/etc/stats.conf' ) {
		# Removes "BLACKHOURS=" and replace the , between numbers with a space
		chomp( my $hours = `grep "BLACKHOURS=" /etc/stats.conf | sed -e 's/.*=//' -e 's/,/ /g'` );
		my @hours = split( ' ', $hours );

		# Subtract the amount of array indices (hours) from 24 to get how many hours are left that stats can run
		my $allowed = 24 - scalar( @hours );

		# if the amount of hours selected is 24, then print stats will never run'
		if ( scalar( @hours ) == 24 ) {
			return "@hours (Allowed time: " , BOLD RED "0 hours - STATS WILL NEVER RUN!" , BOLD WHITE ")";
		} else {
			# If the amount of hours selected is 0, meaning no hours are blacked out, then..
			if ( scalar( @hours ) == 0 ) {
				return DARK GREEN "Never" , BOLD WHITE "(Allowed Time:" , DARK GREEN "24 hours" , BOLD WHITE ")";
			} else {
				# If some horus are blacked out, print the value of @hours (the blacked out hours).
				return BOLD RED "@hours" , BOLD WHITE "(Allowed Time:", DARK GREEN "$allowed hours" , BOLD WHITE ")";
			}
		}
	} else {
		# if /etc/stats.conf doesn't exist (new install probably), then print "Never"
		return DARK GREEN "Never";
	}
}


sub LogsRunEvery {
# Show how often stats are set to ptocess
# Grab cycle_hours and store result in $hours
	chomp( my $hours = `grep "cycle_hours=" /var/cpanel/cpanel.config | sed 's/.*=//'` );

	if ( ! $hours ) {
		return "24";
	} else {
		return "$hours";
	}
}

sub BandwidthRunsEvery {
# Show how often bandwidth is set to process
# Grab bwcycle= and store result in $hours
	chomp( my $hours = `grep "bwcycle=" /var/cpanel/cpanel.config | sed 's/.*=//'` );

	if ( ! $hours ) {
		return "2";
	} else {
		return "$hours";
	}
}

sub IsAvailable {
# See if the stats program is disabled in tweak settings
# greps for the stats prog name in cpanel.config and removes output up to the = sign
	my $prog = shift;
	chomp( my $disabled = `(grep "skip${prog}=" /var/cpanel/cpanel.config | sed 's/.*=//')` );

	if ( $disabled eq 1 or $disabled eq "" ) {
		return BOLD RED "Disabled";
	} else {
		return DARK GREEN "Available to Users";
	}
}

sub IsDefaultOn {
# Make sure we're looking for the stats program in upper case, and display if the stats program is seto to active by default or not
	my $arg = shift;
	if ( -f '/etc/stats.conf' ) {
		chomp( my $prog = `echo $arg | tr "[:lower:]" "[:upper:]"` );
		chomp( my $isdefined = `egrep "DEFAULTGENS=" /etc/stats.conf` );
		chomp( my $ison = `egrep "DEFAULTGENS=.*${prog}" /etc/stats.conf` );
		if ( $isdefined eq "" ) {
			return DARK GREEN "On";
		} else {
			if ( $ison eq "" ) {
				return BOLD RED "Off";
			} else {
				return DARK GREEN "On";
			}
		}
	} else {
		return DARK GREEN "On";
	}
}	

sub AllAllowed {
# Display if per WHM all users are allowed to pick stats programs
	if ( -f '/etc/stats.conf') {
		chomp( my $allowall = `egrep "ALLOWALL=" /etc/stats.conf | sed 's/.*=//'` );
		chomp( my $users = `grep VALIDUSERS /etc/stats.conf | sed -e 's/.*=//' -e 's/,/ /g'` );
		if ( $allowall eq 'yes' ) {
			return DARK GREEN "Yes";
		} elsif ( ! $allowall and ! $users ) {
			return DARK GREEN "No";
		} else {
			return BOLD RED "No";
		}
	} else {
		return DARK GREEN "No";
	}
}

sub UserAllowed {
	# If a user has individually been set to pick stats then show yes, but show no if stats.conf has bad permissions
	if ( -f '/etc/stats.conf' ) {
		my $user = shift;
		my $users = `grep VALIDUSERS /etc/stats.conf | sed -e 's/.*=//' -e 's/,/ /g'`;
		# if the user is set to pick stats, or all users are set to pick stats, and stats.conf has good permissions, then print yes. Otherwise, if the user is set to pick stats and stats.conf has bad permissions, then print no, else print no.
		my $allowall = `grep \"ALLOWALL=yes\" /etc/stats.conf`;
		if ( $users =~ /\b$user\b/ or $allowall ) {
			my $statsconf = `find /etc/stats.conf -perm 644`;
			if ( $statsconf ) {
				print DARK GREEN "Yes\n";
			} 
		} elsif ( $users =~ $user and ! `find /etc/stats.conf -perm 644` ) {
			print BOLD RED "Yes\n";
			print "\n";
			print BOLD RED "*** /etc/stats.conf doesn't have permissions of 644. This will cause user $user to not be able to choose log programs in cPanel, however, the user will still show the ability to choose log programs. ***\n";
		} else {
			print BOLD RED "No\n";
		}			
	} else {
		print BOLD RED "No\n";
	}
	return;
}

sub UserAllowedRegex {
# This function is only needed because the color codes in the yes/no output in UserAllowed() don't work with the expected yes/no output from running that function in GetEnabledDoms().
	if ( -f '/etc/stats.conf' ) {
		my $user = shift;
		my $users = `grep VALIDUSERS /etc/stats.conf | sed -e 's/.*=//' -e 's/,/ /g'`;
		if ( $users =~ $user ) {
			return "Yes";
		} else {
			return "No";
		}
	} else {
		return "No";
	}
}

sub LogDRunning {
# Check if cpanellogd is running. Null output from --check means it is. 
	my $check = `/scripts/restartsrv_cpanellogd --check`;
	if ( ! $check ) {
		return DARK GREEN "Running";
	} else {
		return BOLD RED "Not Running";
	}
}

sub KeepingUp {
# Find out if there is a stats file under /lastrun that is greater than the (stats processing interval * 60 * 60), but only if that file is owned by a current cPanel user
	my @outofdate;
	chomp( my $interval = &LogsRunEvery * 60 * 60);
	my $time = time();
	my @filelist = </var/cpanel/lastrun/*/stats>;
	foreach my $file ( @filelist ) {
		my $mtime = (stat($file))[9];
		my $duration = $time - $mtime;
		chomp( my $user = `echo $file | cut -f5 -d/` );
		if ( $duration > $interval ) {
			if ( -d "/var/cpanel/userdata/$user" ) {
				my $olduser = `ls -la /var/cpanel/lastrun/$user/stats`;
				push ( @outofdate , $olduser );
			}
		}
	}
	
	if ( @outofdate ) {
		return BOLD RED "No" , BOLD WHITE "Users out of date:\n" , BOLD RED "@outofdate";
	} else {
		return DARK GREEN "Yes";
	}	
}

sub UserKeepUp {
# Display if the user's stats are being processed in time
# $interval is running the return value of logsrunevery * 60 * 60 to get the amount of seconds (default of 84400, or 24 hours)
	my $user = shift;
	chomp( my $interval = &LogsRunEvery * 60 * 60 );
	my $time = time();
	my $file = "/var/cpanel/lastrun/$user/stats";
	my $mtime = (stat($file))[9];
	my $duration = $time - $mtime;
	if ( $duration > $interval ) {
		return BOLD RED "No";
	} else {
		return DARK GREEN "Yes";
	}
}

sub BwUserKeepUp {
	# Display if the user's stats are being processed in time
	# $interval is running the return value of logsrunevery * 60 to get the amount of minutes (default of 120, or 2 hours)
	my $user = shift;
	chomp( my $interval = &BandwidthRunsEvery * 60 * 60 );
	my $time = time();
	my $file = "/var/cpanel/lastrun/$user/bandwidth";
	my $mtime = (stat( $file ))[9];
	my $duration = $time - $mtime;
	if ( $duration > $interval ) {
		return BOLD RED "No";
	} else {
		return DARK GREEN "Yes";
	}
}

sub LastRun {
	# Display when the user's stats were last ran
	my $user = shift;
	my $file = "/var/cpanel/lastrun/$user/stats";
	if ( -f $file ) {
		my $mtime = (stat( $file ))[9];
		$mtime = localtime( $mtime );
		return DARK GREEN "$mtime";
	} else {
		return BOLD RED "Never";
	}
}

sub BwLastRun {
# Display when the user's bandwidth processing was last ran
	my $user = shift;
	my $file = "/var/cpanel/lastrun/$user/bandwidth";
	if ( -f $file ) {
		my $mtime = (stat( $file ))[9];
		$mtime = localtime( $mtime );
		return DARK GREEN $mtime;
	} else {
		return BOLD RED "Never";
	}
}

sub Awwwwstats {
# Check to see if awstats.pl doesn't have correct permissions
	my $check = `find /usr/local/cpanel/3rdparty/bin/awstats.pl -perm 0755`;
	if ( ! $check ) {
		print "\n";
		print BOLD RED "AWStats Problem = Yes\n";
		print BOLD RED "/usr/local/cpanel/3rdparty/awstats.pl is not 755 permissions!\n";
	}
}

sub HttpdConf {
# No stats if Apache conf has problems, so check syntax
	my $check = `/usr/local/apache/bin/apachectl configtest 2>&1`;
	if ( $check =~ 'Syntax OK' ) {
		return DARK GREEN "Syntax OK";
	} else {
		return BOLD RED "Syntax Errors ", BOLD WHITE "(Run: httpd configtest)\n\n" , BOLD RED "*** This means that Apache can't do a graceful restart and that the domlogs will be 0 bytes in size, so therefore no new stats will be processed until httpd.conf is fixed! ***\n";  
	}
}

sub WhoCanPick {
# Display users who have been specified to choose stats programs
	if ( -e '/etc/stats.conf' ) {
		chomp( my $users = `grep "VALIDUSERS=" /etc/stats.conf | sed 's/.*=//'` );
		if ( $users eq "" ) {
			print DARK GREEN "Nobody";
		} else {
			print DARK GREEN "$users";
		}
		if ( $users ) {
			chomp( my $check = `find /etc/stats.conf -perm 644` );
			if ( ! $check ) {
				print "\n\n";
				print BOLD RED "*** /etc/stats.conf doesn't have permissions of 644. This will cause users to not be able to choose log programs in cPanel. ***\n";
			}
		} else {
			print DARK GREEN "$users";
		}
	} else {
		print DARK GREEN "Nobody";
	}
	return;
}

sub GetEnabledDoms {
	my $prog = shift;
	chomp( $prog = `echo $prog | tr "[:lower:]" "[:upper:]"` );
	my $user = shift;
	chomp( my $homedir = `grep $user /etc/passwd | cut -d: -f6 | egrep $user\$` );
	chomp( my @alldoms = `egrep "^DNS[0-9]{0,3}=" /var/cpanel/users/$user | cut -f2 -d=` );
	if ( -e "$homedir/tmp/stats.conf" ) {
		my @domains;
		foreach my $dom (@alldoms) {
			chomp( my $capsdom = `echo $dom | tr "[:lower:]" "[:upper:]"` );
			chomp( my $domsetting = `grep "$prog-$capsdom=" $homedir/tmp/stats.conf | sed 's/'$prog'-//' | tr "[:upper:]" "[:lower:]"` );
			if ( $domsetting eq "" ) {
				$dom .= "=no";
				push @domains, $dom;
			} else {
			        push @domains, $domsetting;
			}
		}
		return @domains;
	} else {
		# If the user is new or just hasn't saved their log program choices in cPanel, and the stats program is active
		# by default, then show Yes for each domain as the default then would be On since the user hasn't overridden it in cPanel.
		# If however the stats program is not active by default then show No as stats won't generate for that program unless
		# the user specifically enables it in cPanel.
		if (( &UserAllowedRegex($user) =~ 'Yes' or &AllAllowed =~ 'Yes' ) and ( &IsDefaultOn($prog) =~ 'On' )) {
			my @domains;
			foreach my $dom (@alldoms) {
				chomp( $dom );
				$dom .= "=yes";
				push @domains , "$dom";
			}
			return @domains;
		} else {
			my @domains;
			foreach my $dom (@alldoms) {
				chomp( $dom );
				$dom .= "=no";
				push @domains, $dom;
			}
			return @domains;
		}
	}
}

sub DumpDomainConfig {
	my $prog = shift;
	my $user = shift;
	my @doms = &GetEnabledDoms($prog, $user);
	if ( ! @doms ) {
		print BOLD RED "NO DOMAINS" , BOLD WHITE ":: $prog is available but not active by default. $user " , DARK GREEN "DOES" , BOLD WHITE "have own privs to enable $prog for domains, but hasn't\n";
	} else {
		print DARK GREEN "CAN PICK" , BOLD WHITE "(Per-Domain Config Listed Below)\n";
		foreach my $dom (@doms) {
			#print "  $dom\n";
			my ( $domain , $enabled ) = split ('=' , $dom); 
			print "$domain = ";
			if ( $enabled eq 'yes' ) {
				print BOLD GREEN "$enabled", RESET, "\n";
			} elsif ( $enabled eq 'no' ) {
				print BOLD RED "$enabled", RESET, "\n";
			}
		}
	}
}

sub IsBlocked {
	my $prog = shift;
	my $user = shift;

# This first looks to see if STATGENS exists in the user file.
# If it does then this means an admin override for the user in WHM
# Then see if that line contains the stats program being passed to the function. 
# If it does contain the stats program then that means that program was blocked for that user in WHM at:
# Main >> Server Configuration >> Statistics Software Configuration >> User Permissions >> Choose Users >> Choose Specific Stats Programs for
	chomp( my $statprog = `grep STATGENS /var/cpanel/users/$user | sed 's/.*=//' | tr '[:upper:]' '[:lower:]'` );
	if ( $statprog and $statprog !~ $prog ) {
		print BOLD RED "Blocked\n";
		`touch /tmp/blockedprog`;
	}
}

sub WillRunForUser {
	my $prog = shift;
	my $user = shift;
	# If the stats prog is not set as available in WHM
	if ( &IsAvailable($prog) =~ 'Disabled' ) {
		print BOLD RED "NO DOMAINS" , BOLD WHITE ":: $prog is disabled server wide\n";
	# if the stats prog is blocked by the admin 
	} elsif ( &IsBlocked($prog , $user) =~ 'Blocked' ) {
		print BOLD RED "BLOCKED" , ":: $prog is blocked by the administrator for this user\n";
	} else {
		# If the prog is off, then..
		if ( &IsDefaultOn($prog) =~ 'Off' ) {
			# if the "Allow all users to change their web statistics generating software." is off, then
			if ( &AllAllowed =~ 'No' ) {
				# if the user is added to the list to choose progs, then
				if ( &UserAllowedRegex($user) =~ 'Yes') {
						&DumpDomainConfig($prog , $user);
				} else {
					# but if not, then print that prog is available but not active by default and user does not have privs to enable prog.
					print BOLD RED "NO DOMAINS" , BOLD WHITE ":: $prog is available, but not active by default\n";
					print "\t" , "$user " , BOLD RED "DOES NOT" , BOLD WHITE "have privs to enable $prog for domains\n";
				}
			} else {
				# else, if the user can choose progs, show if prog is active or not for each domain
				&DumpDomainConfig($prog , $user);
			}
		} else {
			# if the allow all users to change stats is yes OR the user is in the allowed list, then show if prog is active or not for each domain.
			if ( &UserAllowedRegex($user) =~ 'Yes' or &AllAllowed =~ 'Yes' ) {
				&DumpDomainConfig($prog , $user);
			} else {
				# else, print that prog is active by default for all domains as the user has no ability to choose log progs
				print DARK GREEN "ALL DOMAINS" , BOLD WHITE ":: $prog is enabled and active by default\n";
			}
		}
	}
	return;
}

sub CanRunLogaholic {
# Check if cPanel is >= 11.31 (when Logaholic was added).
	chomp( my $version = `cut -f1,2 -d. /usr/local/cpanel/version | sed 's/\\.//g'` );
	if ( $version ge '1131' ) {
		return "Yes";
	} else {
		return "No";
	}
}

sub DomainResolves {
# Check to see if user's domains resolve to IPs bound on the server. This doesn't run if --noquery is used.
	my $user = shift;
	my $donotresolve;
	my $timedout;
	my $notbound;
	chomp( my $bound = `/sbin/ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print \$1 }'` );
	# Grab domain list from the cPanel user file
	chomp( my @domlist = `grep ^DNS /var/cpanel/users/$user | cut -f2 -d=` );
	# For each domain in the list we see if google's public DNS can resolve the IP
	foreach my $name (@domlist) {
		my $ip = `dig \@8.8.8.8 +short $name`;
		# If it can't be resolved..
		if ( $ip eq "" ) {
			$donotresolve .= "$name\n";
		# Else if the DNS lookup times out...
		} elsif ( $ip =~ 'connection timed out' ) {
			$timedout .= "$name\n";
		# Else if the domain does resolve, just not to an IP on this server..
		} elsif ( $bound !~ $ip ) {
			$notbound .= "$name\n";
		}
	}
	print "ALL DOMAINS RESOLVE TO SERVER: ";
	# If $donotresolve and $notbound and $timedout are null, meaning all lookups were successful
	if ( ! $donotresolve and ! $notbound and ! $timedout ) {
		print DARK GREEN "Yes\n";
	} else {
		# Otherwise, if one or the other is not null.. 
		if ( $donotresolve or $notbound or $timedout ) {
			print BOLD RED "No\n";
		}
		if ( $donotresolve ) {
			print "The following domains do not resolve at all:\n";
			print BOLD RED "$donotresolve\n";
		}
		if ( $timedout ) {
			print "Lookups for the following domains timed out:\n";
			print BOLD RED "$timedout\n";
		}
		if ( $notbound ) {
			print "The following domains do not point to an IP bound on this server:\n";
			print BOLD RED "$notbound\n";
		}
	}
}		


#####################
# Main Blob of Code #
#####################

# Run the Awwwstats function to see if awstats.pl is executable, and run CheckPerl to verify Perl
&Awwwwstats;

# No arg = general info on web stats setup
if ( ! $user ) {
	print "\n";
	print "Displaying general information on web stats configuration.\n";
	print "To display user configuration, run \"webstatsprobe <cP User>\"\n";
	print "\n";
	print DARK CYAN "[ Web Stats Probe -v$version - Results For:", BOLD YELLOW "System", DARK CYAN "]\n";
	print "\n";
	print "CPANELLOGD: " , &LogDRunning , "\n";
	print "HTTPD CONF: " , &HttpdConf , "\n";
	print "BLACKED OUT: " , &BlackedHours , "\n";
	print "LOG PROCESSING RUNS EVERY: ", DARK GREEN &LogsRunEvery , "hours\n";
	print "BANDWIDTH PROCESSING RUNS EVERY: ", DARK GREEN &BandwidthRunsEvery , "hours\n";
	print "KEEPING UP: " , &KeepingUp , "\n";
	print "CAN ALL USERS PICK: ";
	print &AllAllowed , "\n";
	if ( &AllAllowed =~ 'No' ) {
		print "WHO CAN PICK STATS: ";
		print &WhoCanPick, "\n";
	}
	print "ANALOG: " , &IsAvailable( 'analog' ) , " (Active by Default: " , &IsDefaultOn( 'ANALOG' ) , ")\n";
	print "AWSTATS: " , &IsAvailable( 'awstats' ) , " (Active by Default: " , &IsDefaultOn( 'AWSTATS' ) , ")\n";
	print "WEBALIZER " , &IsAvailable( 'webalizer' ) , " (Active by Default: " , &IsDefaultOn( 'WEBALIZER' ) , ")\n";
	if ( &CanRunLogaholic eq 'Yes' ) {
		print "LOGAHOLIC: " , &IsAvailable( 'logaholic' ) , " (Active by Default: " , &IsDefaultOn( 'LOGAHOLIC' ) , ")\n";
	}
} else {
	# If called with a user argument, let's verify that user exists and display the output
	if ( -e "/var/cpanel/users/$user" and -d "/var/cpanel/userdata/$user" ) {
		print "\n";
		print "Available flags when running \"webstatsprobe <user>\"\n";
		if ( $noquery == 1 ) {
			print "--noquery (turns off DNS lookups for each user domain)\n"
		} else {
			print "None\n";
		}
		print "\n";
		print DARK CYAN "[ Web Stats Probe v$version - Results For:" , BOLD YELLOW $user , DARK CYAN "]\n";
		print "\n";
		# Here we want to test and see if STATGENS is present in the cPanel user file.
		# If it is this means that the server admin has blocked out certain stats
		# applications for the specific users in WHM. If STATGENS exists then we test to see if
		# there are any stats programs listed after STATGENS=. If not then the admin has blocked
		# all stats programs. Yes, we have seen someone do this before.
		chomp( my $statgens = `grep STATGENS /var/cpanel/users/$user` );
		chomp( my $statgens_list = `grep STATGENS /var/cpanel/users/$user | sed 's/.*=//'` );
		if ( $statgens  and ! $statgens_list ) {
			print BOLD RED "*** ALL STATS PROGRAMS BLOCKED FOR USER BY SERVER ADMIN IN WHM ***\n\n";
		}
		# Check if each of the user domains resolve to IP on the server
		if ( $noquery != 0 ) {
			&DomainResolves($user);
		}
		print "KEEPING UP (STATS): " , &UserKeepUp($user) , " (Last Run: " , &LastRun($user) , ")\n";
		print "KEEPING UP (BANDWIDTH): " , &BwUserKeepUp($user), " (Last Run: ", &BwLastRun($user) , ")\n";
		if ( &BwUserKeepUp($user) =~ 'No' ) {
			print "\n";
			print BOLD RED "*** Bandwidth processing isn't keeping up! Please check the eximstats DB for corruption ***\n";
			print "If the eximstats.sends table is corrupted then when runweblogs is ran the smtp rrd file won't generate correctly and the file /var/cpanel/lastrun/$user/bandwidth won't update.\n";
			print BOLD RED "*** Please run: \"mysqlcheck -r eximstats\" ***\n";
			print "\n";
		}
		print "ANALOG: ";
		print &WillRunForUser('analog' , $user);
		print "AWSTATS: ";
	        print &WillRunForUser('awstats' , $user); 	
		print "WEBALIZER: ";
	        print &WillRunForUser('webalizer' , $user);
		if ( &CanRunLogaholic =~ 'Yes' ) {
			print "LOGAHOLIC: ";
			print &WillRunForUser('logaholic' , $user);
		}
		if ( &AllAllowed =~ 'No' and &UserAllowedRegex($user) =~ 'No' ) {
			print "CAN PICK STATS: ";
			print &UserAllowed($user);
		}
		if ( -e '/tmp/blockedprog' ) {
			print "\n";
			print BOLD RED "*** Webstatsprobe reports that one or more statsprograms are BLOCKED for the user by the server admin ***\n";
			print BOLD RED "To correct this issue in WHM, go to:\n";
			print "Server Configuration >> Statistics Software Configuration >> User Permissions >>\n";
			print "Choose Users >> Choose Specific Stats Programs for\n";
			print "\n";
			print "To use the default setting of all apps available, remove the STATGENS line from the cPanel user file.\n";
			unlink '/tmp/blockedprog'; 
		}
	} else {
		# Otherwise we say too bad so sad.
		print "\n";
		print "ERROR: User [ $user ] not found.\n";
		print "You may have entered the wrong username, or /var/cpanel/$user or /var/cpanel/userdata/$user is missing.\n";
		print "Usage: webstatsprobe <cP User>\n";
	}
}
print "\n";
