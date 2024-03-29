#!/usr/local/cpanel/3rdparty/bin/perl
# Copyright 2022, cPanel, L.L.C.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the owner nor the names of its contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
use warnings;
use strict;
use Term::ANSIColor qw(:constants);
$Term::ANSIColor::AUTORESET = 1;
use File::HomeDir;
use Getopt::Long;
use Net::DNS;
use Cpanel::Config::LoadCpConf      ();


my $version = '1.5.8';
my $cycle_hours;
my $bwcycle;
my $prog;
my $StatsProg;

###################################################
# Check to see if the calling user is root or not #
###################################################

die "This script needs to be ran as the root user\n" if $> != 0;

###########################################################
# Parse positional parameters for flags and set variables #
###########################################################

# Set defaults for positional parameters
my $noquery = 0;       # Default to doing DNS queries on user domains
my $nots    = 0;       # Default to displaying Tweak Settings Stats values
my $user    = undef;   # Default to no user to get system stats

GetOptions(
    'noquery' => \$noquery,
    'nots'    => \$nots,
    'user=s'  => \$user,    # =s is for --option with a value
);

# Get # of cores
my $corecnt = qx[ grep -c 'model name' /proc/cpuinfo ];
chomp($corecnt);
# Get Load Average
my ($loadavg) = (split(/\s+/,qx[ cat /proc/loadavg ]))[0];
chomp($loadavg);

if ($loadavg > $corecnt) { 
    print BOLD RED "*** WARNING! Load Average is HIGH - Stats may stall ***\n";
}

# Going to be used later by IsBlocked();
my $blockedprog = 0;

# Verify user file exists for given user
if ( defined $user && !-e "/var/cpanel/users/$user" ) {
    print "\n";
    print "ERROR: User [ $user ] not found.\n";
    print "You may have entered the wrong username, or /var/cpanel/$user or /var/cpanel/userdata/$user is missing.\n";
    print "Usage: webstatsprobe --user <cP User>\n";
    print "\n";
    exit 1;
}

###########################################
# Check if necessary programs are missing #
###########################################

if ( ( $user and $noquery == 0 ) and 
   ( !-x '/sbin/ifconfig' || !-e '/sbin/ifconfig' ) ) {
    die "ifconfig is either missing or not executable, please fix or pass --noquery flag to bypass DNS lookups.\n";
}

#####################
# Open File Handles #
#####################

my $cpconf = Cpanel::Config::LoadCpConf::loadcpconf();

open( my $STATSCONFIG_FH, '<', '/etc/stats.conf' )
  if ( -f "/etc/stats.conf" );    # no die here as stats.conf may not exist

open( my $CPVERSION_FH, '<', '/usr/local/cpanel/version' )
  or die "Could not open /usr/local/cpanel/version, $!\n";

open( my $WWWACCTCONF_FH, '<', '/etc/wwwacct.conf' )
  or die "Could not open /etc/wwwacct.conf, $!\n";

my ( $CPUSER_FH, $CPUSERSTATS_FH );
if ( defined($user) ) {
    open( $CPUSER_FH, '<', "/var/cpanel/users/$user" )
      or die "Could not open /var/cpanel/users/$user, $!\n";

    my $homedir = File::HomeDir::users_home($user);
    # New user won't have stats.conf, so only open if it exists
    if ( -f "$homedir/tmp/stats.conf" ) {
        open( $CPUSERSTATS_FH, '<', "$homedir/tmp/stats.conf" )
          or die "Could not open '$homedir/tmp/stats.conf', $!\n";
    }
}

###################################
# Gather Values For Later Sub Use #
###################################

# If file handles are available, put the settings into hashes to use later

my %stats_settings;
%stats_settings = get_settings($STATSCONFIG_FH) if $STATSCONFIG_FH;

my %cpuser_settings;
%cpuser_settings = get_settings($CPUSER_FH) if $CPUSER_FH;

my %cpuser_stats_settings;
%cpuser_stats_settings = get_settings($CPUSERSTATS_FH) if $CPUSERSTATS_FH;

my %wwwacct_settings;
%wwwacct_settings = get_settings($WWWACCTCONF_FH) if $WWWACCTCONF_FH;

####################
# Main code output #
####################

# No arg = general info on web stats setup
if ( !defined($user) ) {
    print "\n";
    print "Available flags when running \"$0\" (if any):\n";
    print "    --user <cP user> (display stats configuration for a user)\n" if !defined($user);
    print "    --nots           (turns off display of Tweak Settings info)\n" if $nots == 0;
    print "\n";
    print "Displaying general information on web stats configuration.\n";
    print "\n";
    print DARK CYAN "[ Web Stats Probe v$version - Results For:", BOLD YELLOW " System ", DARK CYAN "]\n";
    print "\n";
    if ( !$nots ) {
        print "WHM TWEAK SETTINGS FOR STATS: \n";
        DisplayTS();
        print "\n";
    }
    print "CPANELLOGD: ",  LogDRunning(),  "\n";
    print "HTTPD CONF: ",  HttpdConf(),    "\n";
    print "BLACKED OUT: ", BlackedHours(), "\n";
    print "LOG PROCESSING RUNS EVERY: ", DARK GREEN LogsRunEvery(), " hours\n";
    print "BANDWIDTH PROCESSING RUNS EVERY: ", DARK GREEN BandwidthRunsEvery(), " hours\n";
    print "KEEPING UP: ", KeepingUp(), "\n";
    print "CAN ALL USERS PICK: ";
    print AllAllowed(), "\n";
    if ( AllAllowed() =~ 'No' ) {
        print "WHO CAN PICK STATS: ";
        print WhoCanPick(), "\n";
    }
    print "ANALOG: ",   IsAvailable('analog'),    " (Active by Default: ", IsDefaultOn('ANALOG'),    ")\n";
    print "AWSTATS: ",  IsAvailable('awstats'),   " (Active by Default: ", IsDefaultOn('AWSTATS'),   ")\n";
    print "WEBALIZER ", IsAvailable('webalizer'), " (Active by Default: ", IsDefaultOn('WEBALIZER'), ")\n";

    if ( CanRunLogaholic() eq 'Yes' ) {
        print "LOGAHOLIC: ", IsAvailable('logaholic'), " (Active by Default: ", IsDefaultOn('LOGAHOLIC'), ")\n";
    }
    _check_logstyle();
}
else {
    # If called with a user argument, let's verify that user exists and display
    # the output
    if ( -e $CPUSER_FH and -d "/var/cpanel/userdata/$user" ) {
        print "\n";
        print "Available flags when running \"$0 --<cP user>\" (if any):\n";
        print "    --noquery (turns off DNS lookups for each user domain)\n" if $noquery == 0;
        print "\n";
        print DARK CYAN "[ Web Stats Probe v$version - Results For: ", BOLD YELLOW $user , DARK CYAN " ]\n";
        print "\n";

        # Here we want to test and see if STATGENS is present in the cPanel
        # user file. If it is this means that the server admin has blocked out
        # certain stats applications for the specific users in WHM. If STATGENS
        # exists then we test to see if there are any stats programs listed
        # after STATGENS=. If not then the admin has blocked all stats programs.
        # Yes, we have seen someone do this before.
        if ( defined( $cpuser_settings{'STATGENS'} )
                  and $cpuser_settings{'STATGENS'} eq "" ) {
            print BOLD RED "*** ALL STATS PROGRAMS BLOCKED FOR USER BY SERVER ADMIN IN WHM ***\n\n";
        }

        # If --noquery wasn't specified, then check if each of the user domains resolve to IP on the server
        if (!$noquery) {
            print "ALL DOMAINS RESOLVE TO SERVER: ";
            DomainResolves($user);
        }
        print "KEEPING UP (STATS): ", UserKeepUp($user), " (Last Run: ", LastRun($user), ")\n";
        print "KEEPING UP (BANDWIDTH): ", BwUserKeepUp($user), " (Last Run: ", BwLastRun($user), ")\n";
        if ( BwUserKeepUp($user) =~ 'No' ) {
            print "\n";
            if (-e("/etc/eximstatsdisable")) { 
                print BOLD RED "*** eximstats is disabled! - Bandwidth statistics may be inaccurate ***\n";
            }
            else { 
                print BOLD RED "*** Bandwidth processing isn't keeping up! Checking the eximstats DB for corruption ***\n";
                if (-e("/var/cpanel/eximstats_db.sqlite3.broken.*")) { 
                    print "Found a broken eximstats_db file! Some corruption may have occurred.\n";
                    print "Consider running /usr/local/cpanel/bin/updateeximstats\n";
                }
                else { 
                    print "No broken eximstats_db files found in /var/cpanel\n";
                    print "Restarting cpanellogd...\n";
                    qx[ /usr/local/cpanel/scripts/restartsrv_cpanellogd ];
                }
            }
            print "\n";
        }
        print "ANALOG: ";
        print WillRunForUser( 'analog', $user );
        print "AWSTATS: ";
        print WillRunForUser( 'awstats', $user );
        print "WEBALIZER: ";
        print WillRunForUser( 'webalizer', $user );
        if ( CanRunLogaholic() =~ 'Yes' ) {
            print "LOGAHOLIC: ";
            print WillRunForUser( 'logaholic', $user );
        }
        if ( AllAllowed() =~ 'No' and UserAllowed($user) eq 'No' ) {
            print "CAN PICK STATS: ";
            print DARK GREEN "Yes\n" if UserAllowed($user) eq 'Yes';
            print BOLD RED "No\n"    if UserAllowed($user) eq 'No';
        }
        if ($blockedprog) {
            print "\n";
            print BOLD RED "*** Webstatsprobe reports that one or more statsprograms are BLOCKED for the user by the server admin ***\n";
            print BOLD RED "To correct this issue in WHM, go to:\n";
            print "Server Configuration >> Statistics Software Configuration >> User Permissions >>\n";
            print "Choose Users >> Choose Specific Stats Programs for\n";
            print "\n";
            print "To use the default setting of all apps available, remove the STATGENS line from the cPanel user file.\n";
        }
        # Check if user has configured archive-logs and/or remove-old-archived-logs from Raw Access
    	my $homedir = File::HomeDir::users_home($user);
        if (-e("$homedir/.cpanel-logs")) { 
			print BOLD RED "*** NOTICE: The $user account has a custom log configuration with the following: ***\n" unless(!(-s("$homedir/.cpanel-logs")));
            open(CUSTSETTINGS,"$homedir/.cpanel-logs");
            my @CUSTDATA=<CUSTSETTINGS>;
            close(CUSTSETTINGS);
            my $custsettline;
            my $custname;
            my $custvalue;
            foreach $custsettline(@CUSTDATA) { 
                chomp($custsettline);
                next if ($custsettline eq ""); 
                ($custname,$custvalue)=(split(/=/,$custsettline));
                $custvalue= ($custvalue) ? "Yes" : "No";
                if ($custname eq "archive-logs") { 
                    print "Archive logs in your home directory after each stats run: " . $custvalue . "\n";
                }
                if ($custname eq "remove-old-archived-logs") { 
                    print "Remove previous month\'s archive from your home directory: " . $custvalue . "\n";
                }
            }
        }
    }
}

print "\n";

#######################################
# Misc. checks for stupid user tricks #
#######################################

# Run the Awwwstats function to see if awstats.pl is executable
Awwwwstats();
CheckBadPerms();
print "\n";

###########
# Cleanup #
###########

# If there was no /etc/stats.conf, then no need to close the FH for it.
close($STATSCONFIG_FH) if defined($STATSCONFIG_FH);
close($CPVERSION_FH);

# If $user wasn't supplied as an arg, then no need to close FHs for it..
close($CPUSER_FH)      if defined($user);
close($CPUSERSTATS_FH) if defined($user) and defined($CPUSERSTATS_FH);

close($WWWACCTCONF_FH) if defined($WWWACCTCONF_FH);

################
## Subroutines #
################

sub get_settings {
    my $FH = shift;
    my %settings;
    while (<$FH>) {
        chomp;
        my ( $option, $value );
        if ( $_ =~ m/=/ ) {         ## Equal Sign
            ( $option, $value ) = split('=');
        }
        else {      ## Space
            ( $option, $value ) = split(' ');
        }
        $settings{$option} = $value if defined($value);
    }
    return %settings;
}

sub BlackedHours {
    # Get the blackout hours and display if stats can run within those hours
    if ( $stats_settings{'BLACKHOURS'} ) {

        # Copy the blacked out hours into array @hours, splitting on ','
        my @hours = split( ',', $stats_settings{'BLACKHOURS'} );

        # Subtract the amount of array indices (hours) from 24 to get how many
        # hours are left that stats can run
        my $allowed = 24 - scalar(@hours);

        # if the amount of hours selected is 24, then stats will never run
        if ( scalar(@hours) == 24 ) {
            return "$stats_settings{'BLACKHOURS'}", "(Allowed time: ",
              BOLD RED "0 hours - STATS WILL NEVER RUN!", BOLD WHITE ")";
        }
        else {
            # If the amount of hours selected is 0, meaning no hours are blacked
            # out, then..
            if ( scalar(@hours) == 0 ) {
                return DARK GREEN "Never ",
                  BOLD WHITE "(Allowed Time: ", DARK GREEN "24 hours", BOLD WHITE ")";
            }
            else {
                # If some hours are blacked out, print the blacked out hours.
                return BOLD RED "$stats_settings{'BLACKHOURS'} ", BOLD WHITE "(Allowed Time: ", DARK GREEN "$allowed hours", BOLD WHITE ")";
            }
        }
    }
    else {
        # if /etc/stats.conf doesn't exist or does but BLACKHOURS not set, then
        # print "Never"
        return DARK GREEN "Never ", BOLD WHITE "(Allowed Time: ", DARK GREEN "24 hours", BOLD WHITE ")";
    }
    return;
}

sub LogsRunEvery {
 # Show how often stats are set to process, if value not set then return default of 24.
	$cycle_hours = $cpconf->{'cycle_hours'};
	return $cycle_hours ? $cycle_hours : 24;
}

sub BandwidthRunsEvery {
    # Show how often bandwidth is set to process, if value not set then return default of 2.
	$bwcycle = $cpconf->{'bwcycle'};
    return $bwcycle ? $bwcycle : 2;
}

sub IsAvailable {
 # See if the stats program is disabled in tweak settings, return Disabled or Available
    $prog = 'skip' . shift;
	$StatsProg = $cpconf->{$prog};
	if ($StatsProg == 1) { 
        return BOLD RED 'Disabled by root';
    }
    else {
        return DARK GREEN 'Available to Users';
    }
    return;
}

sub IsDefaultOn {
   # Make sure we're looking for the stats program in upper case, and display if
   # the stats program is set to to active by default or not
    my $prog = uc(shift);
    if (%stats_settings) {
        if ( !exists( $stats_settings{'DEFAULTGENS'} ) ) {
            # If no DEFAULTGENS in /etc/stats.conf
            return DARK GREEN 'On';
        }
        else {
            if ( $stats_settings{'DEFAULTGENS'} !~ $prog ) {
                # Else it is there but the specific prog name isn't in the DEFAULTGENS line
                # This also takes into account DEFAULTGENS=0 which means all progs set to not active by default
                return BOLD RED 'Off';
            }
            elsif ( $stats_settings{'DEFAULTGENS'} =~ $prog
                and IsAvailable( lc($prog) ) =~ 'Disabled' ) {
                   # Else, if the prog is in DEFAULTGENS (meaning it was set to Active by default,
                   # but the prog was then Disabled
                return BOLD RED 'Off';
            }
            else {
                return DARK GREEN 'On';
            }
        }
    }
    else {
        # Stats haven't been customized at all in WHM, so no stats.conf yet
        if ( IsAvailable( lc($prog) ) =~ 'Available' ) {
            return DARK GREEN 'On';
        }
        elsif ( IsAvailable( lc($prog) ) =~ 'Disabled' ) {
            return BOLD RED 'Off';
        }
    }
    return;
}

sub _check_logstyle {
    if ( %wwwacct_settings ) {
        if ( exists( $wwwacct_settings{'LOGSTYLE'} ) && $wwwacct_settings{'LOGSTYLE'} eq 'common' ) {
            print BOLD RED "*** Apache Access Log Style is NOT set to combined, stats may not run ***\n";
        }
    }
    return;
}

sub AllAllowed {
    # Display if per WHM all users are allowed to pick stats programs
    if (%stats_settings) {
        if ( exists($stats_settings{'ALLOWALL'})
                && $stats_settings{'ALLOWALL'} eq 'yes' ) {
            return DARK GREEN 'Yes';
        }
        elsif ( !$stats_settings{'ALLOWALL'}
            || !$stats_settings{'VALIDUSERS'} ) {
            # Else if ALLOWALL and
            # VALIDUSERS had no values
            return DARK GREEN 'No';
        }
        else {
            # else if ALLOWALL is not equal to yes
            return BOLD RED 'No';
        }
    }
    else {
        # If /etc/stats.conf doesn't exist
        return DARK GREEN 'No';
    }
    return;
}

sub UserAllowed {
    # This UserAllowed function is called by the main body and is necessary to
    # output the warning for stats.conf. This function however is needed when
    # only yes/no output is required by other functions which call it such as
    # GetEnabledDoms().
    if (%stats_settings) {
        my $user = shift;
        if (    $stats_settings{'VALIDUSERS'}
            and $stats_settings{'VALIDUSERS'} =~ /\b$user\b/ ) {
            return 'Yes';
        }
        else {
            # Else there are no users who can pick stat progs or supplied arg user
            # isn't in the list
            return 'No';
        }
    }
    else {
        # Else if there are no users configured who can choose their own progs
        return 'No';
    }
    return;
}

sub LogDRunning {
    # Check if cpanellogd is running. Null output from --check means it is.
    # in 11.50, we changed the output of the restartsrv_* scripts.
    my $check = 0;
    $check = qx[ /scripts/restartsrv_cpanellogd --check ];
    if ($check =~ m/passed the check/) { 
         $check=1;
    }

    return ($check) ? return DARK GREEN 'Running' : BOLD RED 'Not Running';
}

sub KeepingUp {
    # Find out if there is a stats file under /lastrun that is greater than the
    # (stats processing interval * 60 * 60), but only if that file is owned by a
    # current cPanel user
    my @outofdate;
    my $interval = LogsRunEvery() * 60 * 60;
    my $time     = time();
    my @filelist = glob '/var/cpanel/lastrun/*/stats';

    foreach my $file (@filelist) {
        my $mtime    = ( stat($file) )[9];
        my $duration = $time - $mtime;

        # now let's remove '/var/cpanel/lastrun', then '/stats/' so we can
        # get just the username
        my $user = $file;
        $user    =~ s/\/var\/cpanel\/lastrun\///;
        $user    =~ s/\/stats//;
        if ( $duration > $interval and -d "/var/cpanel/userdata/$user" ) {
            my $olduser = ( qx(ls -la /var/cpanel/lastrun/$user/stats) ) ? $user : "";;
            push( @outofdate, $olduser ) if ( $olduser );
        }
    }

    if (@outofdate) {
        return BOLD RED 'No', BOLD WHITE "Users out of date:\n", BOLD RED "@outofdate";
    }
    else {
        return DARK GREEN 'Yes';
    }
    return;
}

sub UserKeepUp {
    # Display if the user's stats are being processed in time
    # $interval is running the return value of logsrunevery * 60 * 60 to get the
    # amount of seconds (default of 84400, or 24 hours)
    my $user     = shift;
    my $interval = LogsRunEvery() * 60 * 60;
    my $time     = time();
    my $file     = "/var/cpanel/lastrun/$user/stats";

    if ( -f $file ) {    # necessary as as file won't exist on a new user
        my $mtime    = ( stat($file) )[9];
        my $duration = $time - $mtime;
        return ( $duration > $interval ) ? BOLD RED 'No' : DARK GREEN 'Yes';
    }
    else {
        return BOLD RED "Hasn't processed yet";
    }
    return;
}

sub BwUserKeepUp {
    # Display if the user's stats are being processed in time
    # $interval is running the return value of logsrunevery * 60 to get the
    # amount of minutes (default of 120, or 2 hours)
    my $user     = shift;
    my $interval = BandwidthRunsEvery() * 60 * 60;
    my $time     = time();
    my $file     = "/var/cpanel/lastrun/$user/bandwidth";

    # Nessessary as file won't exist on a new user
    if ( -f $file ) {
        my $mtime    = ( stat($file) )[9];
        my $duration = $time - $mtime;
        return ( $duration > $interval ) ? BOLD RED 'No' : DARK GREEN 'Yes';
    }
    else {
        return BOLD RED "Hasn't been processed yet";
    }
    return;
}

sub LastRun {
    # Display when the user's stats were last ran
    my $user = shift;
    my $file = "/var/cpanel/lastrun/$user/stats";

    if ( -f $file ) {
        my $mtime = ( stat($file) )[9];
        $mtime = localtime($mtime);
        return DARK GREEN $mtime;
    }
    else {
        return BOLD RED 'Never';
    }
    return;
}

sub BwLastRun {
    # Display when the user's bandwidth processing was last ran
    my $user = shift;
    my $file = "/var/cpanel/lastrun/$user/bandwidth";

    if ( -f $file ) {
        my $mtime = ( stat($file) )[9];
        $mtime = localtime($mtime);
        return DARK GREEN $mtime;
    }
    else {
        return BOLD RED 'Never';
    }
    return;
}

sub Awwwwstats {
    # Check to see if awstats.pl doesn't have correct permissions
    my $awstats = '/usr/local/cpanel/3rdparty/bin/awstats.pl';
    return if (!(-e($awstats))); 
    my $mode = sprintf '%04o', ( stat $awstats )[2] & 07777;

    if ( $mode ne '0755' ) {
        print "\n";
        print BOLD RED "AWStats Problem = Yes\n";
        print BOLD RED "/usr/local/cpanel/3rdparty/bin/awstats.pl is not 755 permissions!\n";
    }
    return;
}

sub CheckBadPerms {
    if ( defined($STATSCONFIG_FH) ) {
        my $mode = sprintf '%04o', ( stat $STATSCONFIG_FH )[2] & 07777;
        if ( $mode ne '0644' ) {
            print BOLD RED "*** /etc/stats.conf doesn't have permissions of 644. If users have the ability to choose stat programs, this will cause the programs to be locked out by administrator in cPanel. ***\n";
        }
    }
    return;
}

sub HttpdConf {
    # No stats if Apache conf has problems, so check syntax
    my $check = qx( httpd -t 2>&1);

    if ( $check =~ 'Syntax OK' ) {
        return DARK GREEN 'Syntax OK';
    }
    else {
        return BOLD RED 'Syntax Errors ', BOLD WHITE "(Run: httpd -t)\n\n",
          BOLD RED
"*** This means that Apache can't do a graceful restart and that the domlogs will be 0 bytes in size, so therefore no new stats will be processed until httpd.conf is fixed! ***\n";
    }
    return;
}

sub WhoCanPick {
    # Display users who have been specified to choose stats programs
    if (%stats_settings) {
        if ( $stats_settings{'VALIDUSERS'} ) {
            print DARK GREEN $stats_settings{'VALIDUSERS'};
        }
        else {
            # If there is no VALIDUSERS or it's false
            print DARK GREEN 'Nobody';
        }
    }
    else {
        # If stats.conf doesn't exist yet, then no users can choose (default behavior)
        print DARK GREEN 'Nobody';
    }
    return;
}

sub GetEnabledDoms {
    my $prog = uc(shift);
    my $user = shift;
    my @alldoms;
    my @domains;

    while ( my ( $param,$value ) = each %cpuser_settings ) {
        # If $param has a value and the line starts with DNS
        # we put the domain name in @alldoms
        push( @alldoms, $value ) if ( defined($param) and $param =~ /\ADNS/ );
    }

    # If $homedir/tmp/stats.conf exists then for each domain we want to see if
    # $prog-domainname eq yes or no
    if (%cpuser_stats_settings) {
        foreach my $dom (@alldoms) {
            my $capsdom = uc($dom);
            # $homedir/tmp/stats.conf contains the domain and it =yes (stats 
            # checked by user) or if a domain has been added but the domin list
            # in cPanel hasn't been re-saved yet then we display =yes,
            # otherwise =no.
            if ( ($cpuser_stats_settings{"$prog-$capsdom"} 
              && $cpuser_stats_settings{"$prog-$capsdom"} eq 'yes' )
              || !$cpuser_stats_settings{"$prog-$capsdom"} ) {
                push( @domains, "$dom=yes" );
            }
            else {
                push( @domains, "$dom=no" );
            }
        }
        return @domains;
    }
    else {
        # If the user is new or just hasn't saved their log program choices in
        # cPanel, and the stats program is active by default, then show Yes for
        # each domain as the default then would be On since the user hasn't
        # overridden it in cPanel.
        if ( ( UserAllowed($user) =~ 'Yes' or AllAllowed =~ 'Yes' )
            and ( IsDefaultOn($prog) =~ 'On' ) ) {

            foreach my $dom (@alldoms) {
                $dom .= '=yes';
                push( @domains, $dom );
            }
            return @domains;
        }
        else {
            # If however the stats program is not active by
            # default then show No as stats won't generate for that program unless
            # the user specifically enables it in cPanel.
            my @domains;
            foreach my $dom (@alldoms) {
                $dom .= "=no";
                push( @domains, $dom );
            }
            return @domains;
        }
    }
    return;
}

sub DumpDomainConfig {
    my $prog = shift;
    my $user = shift;
    my @doms = GetEnabledDoms( $prog, $user );

    if ( !@doms ) {
        print BOLD RED "NO DOMAINS",
          BOLD WHITE " :: $prog is available but not active by default. $user ",
          DARK GREEN "DOES ",
          BOLD WHITE "have own privs to enable $prog for domains, but hasn't\n";
    }
    else {
        print DARK GREEN "CAN PICK ", BOLD WHITE "(Per-Domain Config Listed Below)\n";
        foreach my $dom (@doms) {
            my ( $domain, $enabled ) = split( '=', $dom );
            print "  $domain = ";
            if ( $enabled eq 'yes' ) {
                print DARK GREEN "$enabled\n";
            }
            elsif ( $enabled eq 'no' ) {
                print BOLD RED "$enabled\n";
            }
        }
    }
    return;
}

sub IsBlocked {
    my $prog = uc(shift);
    my $user = shift;

    # This first looks to see if STATGENS exists in the user file and STATGENS
    # does NOT contain $prog. # If $prog is not found then this means $prog is
    # blocked by the admin in WHM at: # Main >> Server Configuration >>
    # Statistics Software Configuration >> User Permissions >> Choose Users >>
    # Choose Specific Stats Programs for
    if (    $cpuser_settings{'STATGENS'}
         && $cpuser_settings{'STATGENS'} !~ $prog ) {

        $blockedprog = 1;
        return 'Blocked';
    }
    else {
        return '';
    }
}

sub WillRunForUser {
    my $prog = shift;
    my $user = shift;

    # If the stats prog is not set as available in WHM
    if ( IsAvailable($prog) =~ 'Disabled' ) {
        print BOLD RED "NO DOMAINS ", BOLD WHITE ":: $prog is disabled server wide\n";

        # if the stats prog is blocked by the admin
    }
    elsif ( IsBlocked( $prog, $user ) eq 'Blocked' ) {
        print BOLD RED "BLOCKED", BOLD WHITE ":: $prog is blocked by the administrator for this user\n";
    }
    else {
        # If the prog is off, then..
        if ( IsDefaultOn($prog) =~ 'Off' ) {

            # if the "Allow all users to change their web statistics generating
            # software." is off, then
            if ( AllAllowed =~ 'No' ) {

                # if the user is added to the list to choose progs, then
                if ( UserAllowed($user) =~ 'Yes' ) {
                    DumpDomainConfig( $prog, $user );
                }
                else {
                    # but if not, then print that prog is available but not
                    # active by default and user does not have privs to enable
                    # prog.
                    print BOLD RED "NO DOMAINS", BOLD WHITE " :: $prog is available, but not active by default\n";
                    print "\t", "$user ", BOLD RED "DOES NOT", BOLD WHITE " have privs to enable $prog for domains\n";
                }
            }
            else {
                # else, AllAllowed is yes, so show if prog is active or not for
                # each domain
                DumpDomainConfig( $prog, $user );
            }
        }
        else {
            # if the allow all users to change stats is yes OR the user is in
            # the allowed list, then show if prog is active or not for each
            # domain.
            if ( UserAllowed($user) =~ 'Yes' or AllAllowed() =~ 'Yes' ) {
                DumpDomainConfig( $prog, $user );
            }
            else {
                # else, print that prog is active by default for all domains as
                # the user has no ability to choose log progs
                print DARK GREEN "ALL DOMAINS", BOLD WHITE ":: $prog is enabled and active by default\n";
            }
        }
    }
    return;
}

sub CanRunLogaholic {
    # Check if cPanel is >= 11.31 (when Logaholic was added).
    while (<$CPVERSION_FH>) {
        my $version = $_;
        $version =~ s/\.//g;    # remove the periods to compare it lexically
        #return ( $version ge '1131' ) ? 'Yes' : 'No';
        # We are removing logaholic again in 11.48.  
        return ( $version ge '1131' and $version lt '1148' ) ? 'Yes' : 'No';
    }
    return;
}

sub DomainResolves {

    # Check to see if user's domains resolve to IPs bound on the server.
    # This doesn't run if --noquery is used.

    my $user = shift;
    my $donotresolve;
    my $timedout;
    my $notbound;
    my $ip;
    my @domlist;

    # Instantiate resolver object to look up domain names.
    my $res = Net::DNS::Resolver->new;

    # See what IPs are bound on the system
    my $iplist = qx( ip addr show);
    if ( -e '/var/cpanel/cpnat' ) {
        $iplist .= qx(cat '/var/cpanel/cpnat');
    }
    chomp($iplist);

    # Grab domain list from the cPanel user file
    while ( my ( $key, $value ) = each %cpuser_settings ) {
        push( @domlist, $value ) if ( $key =~ /^DNS/ ); # If $key line starts with DNS
    }

    # For each domain in the list we see if we can resolve the IP
    foreach my $name (@domlist) {
        my $query = $res->query( $name, 'A' );
        if ($query) {
            foreach my $rr ( grep { $_->type eq 'A' } $query->answer ) {
                $ip = $rr->address;
            }
            # If the domain resolves, just not to an IP on this server
            if ( $iplist !~ qr/$ip/ ) {
                $notbound .= "$name [$ip]\n";
            }
        }
        else {
            # If it doesn't resolve at all (NXDOMAIN)
            my $error_string = $res->errorstring;
            if ( $error_string eq 'NXDOMAIN' ) {
                $donotresolve .= "$name [NXDOMAIN]\n";
            }
            elsif ( $error_string eq 'Send error: Operation not permitted' ) {
                $timedout .= "$name\n";
            }
        }
    }

    # If $donotresolve and $notbound and $timedout are null, meaning all lookups
    # were successful
    if ( !$donotresolve && !$notbound && !$timedout ) {
        print DARK GREEN "Yes\n";
    }
    else {
        # Otherwise, if one or the other is not null..
        if ( $donotresolve || $notbound || $timedout ) {
            print BOLD RED "No\n";
        }
        if ($donotresolve) {
            print "The following domains do not resolve at all:\n";
            print BOLD RED "$donotresolve\n";
        }
        if ($timedout) {
            print "Lookups for the following domains timed out or could not be completed:\n";
            print BOLD RED "$timedout\n";
        }
        if ($notbound) {
            print "The following domains do not point to an IP bound on this server:\n";
            print BOLD RED "$notbound\n";
        }
    }
    return;
}

sub DisplayTS {
    print "Awstats reverse DNS resolution: ";
    if ( $cpconf->{'awstatsreversedns'} ) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }

    print "Allow users to update Awstats from cPanel: ";
    if ( $cpconf->{'awstatsbrowserupdate'} ) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }

    print "Delete each domain's access logs after stats run: ";
    if ( $cpconf->{'dumplogs'} ) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }

	print "Archive logs in users home directory after each stats run (user configurable): ";
    if ( $cpconf->{'default_archive-logs'} ) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }
	
	print "Remove previous month\'s archive from users homedir (user configurable): ";
    if ( $cpconf->{'default_remove-old-archived-logs'}) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }
	
	print "Keep master FTP log file: ";
    if ( $cpconf->{'keepftplogs'}) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }

	print "Keep log files at end of month: ";
    if ( $cpconf->{'keeplogs'}) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }
	
	print "Keep stats logs: ";
    if ( $cpconf->{'keepstatslog'}) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }
	
	print "Piped Logging Enabled: ";
    if ( $cpconf->{'enable_piped_logs'}) {
        print DARK GREEN "On\n";
    }
    else {
        print DARK GREEN "Off\n";
    }
	
	print "Stats log level: ";
    print DARK GREEN $cpconf->{'statsloglevel'} . "\n";
	
	print "Log rotation size (in megabytes): ";
    print DARK GREEN $cpconf->{'rotatelogs_size_threshhold_in_megabytes'} . "\n";
	
    print "Extra CPUs for server load [ Cores: $corecnt ]: ";
    print DARK GREEN $cpconf->{'extracpus'} . "\n";

    return;
}
