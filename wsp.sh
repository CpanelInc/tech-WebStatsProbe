#!/usr/bin/env bash
# cPanel, Inc.
# <= 0.5 Written by: Brian Oates
# >= 0.6 by: Paul Trost

version="1.9.4"

# TODO
# check if prog enabled and /home/user/tmp/$prog is missing

## Changelog


#############################
# DEPRECATED, PRINT WARNING #
#############################

printf "%s\n" "This script is deprecated and no longer maintained. Please use webstatsprobe.pl instead!"
printf "%s\n" "wget webstatsprobe.cptechs.info/webstatsprobe.pl"
exit 1


################################
# Verify script called as root #
################################

if [[ "$EUID" -ne 0 ]]; then
    printf "\n" "This script must be run as root" 1>&2
    exit 1
fi

# Set defaults for positional parameters
noquery=0 # Default to doing DNS queries on user domains

# Parse positional parameters for flags and set variables if argument is present
for i in $@; do
	# if any of the arguments don't contain "--" then make that argument the user variable
	if [[ ! "$i" =~ \-\- ]]; then
		user=$i
	fi

	# noquery is used to turning off DNS lookups for user domains when webstatsprobe called against a user
	if [[ "$i" =~ "--noquery" ]]; then
		noquery=1
	fi
done


###########################################
# Check if necessary programs are missing #
###########################################

if [[ ! -x '/usr/bin/dig' ]] && [[ $noquery -eq 0 ]]; then
    printf "%b\n" "Dig is either missing or not executable, please fix or pass --noquery flag to bypass DNS lookups."
    exit 1
fi


#####################
# Open File Handles #
#####################

if [[ -f '/var/cpanel/cpanel.config' ]]; then
    cpconfig_fh=$(<'/var/cpanel/cpanel.config')
fi

if [[ -f '/etc/stats.conf' ]]; then
    stats_fh=$(<'/etc/stats.conf')
fi

cpversion_fh=$(<'/usr/local/cpanel/version')

if [[ "$user" ]]; then
    cpuser_fh=$(<"/var/cpanel/users/$user")
fi


#############
# Functions #
#############
BlackedHours() {
# Get the blackout hours and display if stats can run within those hours
if [[ "$stats_fh" ]]; then
	# Removes "BLACKHOURS=" and then replace the , between numbers with a space
	hours=( $(echo "$stats_fh" | grep "BLACKHOURS=" | sed -e 's/.*=//' -e 's/,/ /g')) 

	# Put the contents (blackout hours) from the hours array into the hourstr variable
	hourstr=${hours[*]}

	# Subtract the amount of array indices (hours) from 24 to get how many hours are left that stats can run
	allowed=$((24 - ${#hours[@]}))

	# if the amount of elements is 24 (meaning all hours selected to blackout in WHM), then print 'stats will never run'
	if [[ "${#hours[@]}" = 24 ]]; then 
		printf "%b\n" "${hourstr// /,} (Allowed Time: \033[1;31m0 hours - STATS WILL NEVER RUN!\033[0m)"
	else
		# If the amount of elements is 0, meaning some hours are blacked out, then..
		if [[ "${#hours[@]}" = 0 ]]; then
			# if there are no indices (hours blacked out) then print 'allowed 24 hours'
			printf "%b\n" "\033[0;32mNever\033[0m (Allowed Time: \033[0;32m24 hours\033[0m)"
		else
				# print the value of $hourstr (number of blacked out hours) and replace the space separating them with a "," and print the hours stats allowed to run.
			printf "%b\n" "\033[1;31m${hourstr// /,}\033[0m (Allowed Time: \033[0;32m${allowed} hours\033[0m)"
		fi
	fi
else 
	# if /etc/stats.conf doesn't exist then print "Never"
	printf "%b\n" "\033[0;32mNever\033[0m"
fi
}

LogsRunEvery() {
# Show how often stats are set to process
# Removes "cycle_hours" and store result in $hours 
hours=$(echo "$cpconfig_fh" | grep "cycle_hours=")
hours=${hours#*=} # Use only value after the =

if [[ -z "$hours" ]]; then
	printf "%b\n" "24"
else
	printf "%b\n" "$hours"
fi
}

BandwidthRunsEvery() {
# Show how oftern bandwidth is set to process
# Removes "bwcycle=" and store result in $hours
hours=$(echo "$cpconfig_fh" | grep "bwcycle=")
hours=${hours#*=} # Use only value after the =
if [[ -z "$hours" ]]; then
	printf "%b\n" "2"
else
	printf "%b\n" "$hours"
fi
}

IsAvailable() {
# See if the stats program is disabled in Tweak Settings
# greps for the stats prog name in cpanel.conf and removes output up to the = sign
prog=$1
disabled=$(echo "$cpconfig_fh" | grep "skip${prog}=")
disabled=${disabled#*=} # Use only value after the =
if [[ "$disabled" = "1" ]] ||  [[ -z "$disabled" ]]; then
	printf "%b\n" "\033[1;31mDisabled\033[0m"
elif [[ "$disabled" = "0" ]]; then
	printf "%b\n" "\033[0;32mAvailable to Users\033[0m"
fi
}

IsDefaultOn() {
# Make sure we're looking for the stats program in upper case, and display if the stats program is set to active by default or not
if [[ "$stats_fh"  ]]; then
prog=$(echo ${1} | tr "[:lower:]" "[:upper:]")
lcprog=$(echo ${1} | tr "[:upper:]" "[:lower:]")
isdefined=$(echo "$stats_fh" | grep "DEFAULTGENS=")
ison=$(echo "$stats_fh" | egrep "DEFAULTGENS=.*${prog}")
	if [[ -z "$isdefined" ]]; then
		printf "%b\n" "\033[0;32mOn\033[0m"
	else    
		if [[ -z "$ison" ]]; then
			printf "%b\n" "\033[1;31mOff\033[0m"
		elif [[ "$ison" ]] && [[ $(IsAvailable "$lcprog") =~ 'Disabled' ]]; then
			printf "%b\n" "\033[1;31mOff\033[0m"
        elif [[ "$ison" ]] && [[ "$isdefined" =~ '0' ]]; then
            printf "%b\n" "\033[1;31mOff\033[0m"
		else
			printf "%b\n" "\033[0;32mOn\033[0m"
		fi
	fi
else
	printf "%b\n" "\033[0;32mOn\033[0m"
fi
}

AllAllowed() {
# Display if per WHM all users are allowed to pick stats programs
if [[ "$stats_fh" ]]; then
	allowall=$(echo "$stats_fh" | grep "ALLOWALL=")
    allowall=${allowall#*=}
	users=$(echo "$stats_fh" | grep VALIDUSERS)
    users=${users#*=}
	if [[ "$allowall" = yes ]]; then
		printf "%b\n" "\033[0;32mYes\033[0m"
	elif [[ -z "$allowall" ]] && [[ -z "$users" ]]; then
		printf "%b\n" "\033[0;32mNo\033[0m"
	else
		printf "%b\n" "\033[1;31mNo\033[0m"
	fi
else
	printf "%b\n" "\033[0;32mNo\033[0m"
fi
}

UserAllowed() {
# If a user has individually been set to pick stats then show yes, but show no if stats.conf has bad permissions
if [[ "$stats_fh" ]]; then
	user=\\b$1\\b
    stats_fh_perms=$(stat -c %a /etc/stats.conf)
	# if the user is set to pick stats, or all users are set to pick stats, and stats.conf has good permissons, then print yes, otherwise
	# if the user is set to pick stats and stats.conf has bad permissions, then print no, else print no.  
	if ( [[ "$stats_fh" =~ $user ]] || [[ "$stats_fh" =~ "ALLOWALL=yes" ]] ) && [ "$stats_fh_perms" = 644 ]; then
		printf "%b\n" "\033[0;32mYes\033[0m"
	elif  [[ "$stats_fh" =~ $user ]] && [[ "$stats_fh_perms" != 644 ]]; then
		printf "%b\n" "\033[1;31mYes\033[0m"
		printf "\n"
		printf "%b\n" "\033[1;31m*** /etc/stats.conf doesn't have permissions of 644. This will cause user $1 to not be able to choose log programs in cPanel, however, the user will still show ability to choose log programs. ***\033[0m"
	else
		printf "%b\n" "\033[1;31mNo \033[0m"
	fi
else
	printf "%b\n" "\033[1;31mNo\033[0m"
fi
}

UserAllowedRegex() {
# This function is only needed because the color codes in the yes/no output in UserAllowed() don't work with the expected yes/no output from running that function in GetEnabledDoms()
if [[ "$stats_fh" ]]; then
	user=\\b$1\\b
	if [[ "$stats_fh" =~ $user ]]; then
		printf "%b\n" "Yes"
	else
		printf "%b\n" "No"
	fi
else	
	printf "%b\n" "No"
fi
}


LogDRunning() {
# Check if cpanellogd is running. Null output from --check means it is.
check=$(/scripts/restartsrv_cpanellogd --check)
if [[ -z "$check" ]]; then
	printf "%b\n" "\033[0;32mRunning\033[0m"
else
	printf "%b\n" "\033[1;31mNot Running\033[0m"
fi
}

KeepingUp() {
# Find out if there is a stats file under /lastrun that is greater than the (stats processing interval * 60), but only if that file is owned by a current cPanel user
interval=$(($(LogsRunEvery) * 60));
oldstats=$(find /var/cpanel/lastrun -type f -name 'stats' -mmin +${interval} -exec ls {} \; 2>/dev/null)
if [[ -n "$oldstats" ]]; then
	users=$(/bin/ls -A /var/cpanel/userdata)
	for line in $(echo $oldstats); do
		cpuser=$(echo $line | cut -f5 -d/)
		if [[ $(echo $users | grep $cpuser) ]]; then
		baduser=$(echo $baduser $line)
		fi
	done
fi
if [[ -n "$baduser" ]]; then
	printf "%b\n" "\033[1;31mNo\033[0m Users out of date:\033[0m"
	printf "%b\n" "\033[1;31m$(ls -la $baduser) \033[0m"
else
	printf "%b\n" "\033[0;32mYes \033[0m"
fi
}

UserKeepUp() {
# Display if the user's stats are being processed in time
# $interval is running the return value of logsrunevery * 60 to get the amount of minutes (default of 1440, or 24 hours)
user=$1
interval=$(($(LogsRunEvery) * 60))
oldstats=$(find /var/cpanel/lastrun/$user -type f -name 'stats' -mmin +${interval} -exec ls -l {} \;)
if [[ -z "$oldstats" ]]; then
	printf "%b\n" "\033[0;32mYes\033[0m"
else
	printf "%b\n" "\033[1;31mNo\033[0m"
fi
}

BwUserKeepUp() {
# Display if the user's stats are being processed in time
# $interval is running the return value of logsrunevery * 60 to get the amount of minutes (default of 120, or 2 hours)
user=$1
interval=$(($(BandwidthRunsEvery) * 60))
oldstats=$(find /var/cpanel/lastrun/$user -type f -name 'bandwidth' -mmin +${interval} -exec ls -l {} \;)
if [[ -z "$oldstats" ]]; then
	printf "%b\n" "\033[0;32mYes\033[0m"
else
	printf "%b\n" "\033[1;31mNo\033[0m"
fi
}

LastRun() {
# Display when the user's stats were last ran
user=$1
if [[ -f "/var/cpanel/lastrun/$user/stats" ]]; then
	mtime=$(stat "/var/cpanel/lastrun/${user}/stats" | grep 'Modify:' | sed 's/Modify: //' | sed 's/\..*//')
	printf "%b\n" "\033[0;32m$mtime\033[0m"
else
	printf "%b\n" "\033[1;31mNever\033[0m"
fi
}

BwLastRun() {
# Display when the user's bandwidth processing was last ran
user=$1
if [[ -f "/var/cpanel/lastrun/${user}/bandwidth" ]]; then
	mtime=$(stat "/var/cpanel/lastrun/${user}/bandwidth" | grep 'Modify:' | sed 's/Modify: //' | sed 's/\..*//')
	printf "%b\n" "\033[0;32m$mtime\033[0m"
else
	printf "%b\n" "\033[1;31mNever\033[0m"
fi
}

Awwwwstats() {
# Check to see if awstats.pl doesn't have correct permissions
check=$(find "/usr/local/cpanel/3rdparty/bin/awstats.pl" -perm 0755)
if [[ -z "$check" ]]; then
	printf "\n"
	printf "%b\n" "\033[1;31mAWStats Problem = YES\n/usr/local/cpanel/3rdparty/bin/awstats.pl is not 755 permissions!\033[0m"
fi
}

CheckPerl() {
# If /usr/bin/perl is a file and not a link, and /usr/local/bin/perl is file and not a link, then
if [[ -f '/usr/bin/perl' ]] && ! [[ -L '/usr/bin/perl' ]] && [[ -f '/usr/local/bin/perl' ]] && ! [[ -L '/usr/local/bin/perl' ]]; then
	printf "%b\n" && printf "%b\n" "\033[1;31m*** Conflicting Perl binaries found at /usr/bin/perl and /usr/local/bin/perl ***\033[0m"
	printf "%b\n" "\033[1;31m*** You may want to run /scripts/fixperl, then /scripts/checkperlmodules --full --force ***\033[0m"

	# If /usr/bin/perl is a link, and /usr/local/bin/perl is a file, then 
	elif [[ -L '/usr/bin/perl' ]] && [[ -f '/usr/local/bin/perl' ]]; then
		check=$(find '/usr/local/bin/perl' -perm 0755)
		if [[ -z "$check" ]]; then
			printf "%b\n" && printf "%b\n" "\033[1;31m/usr/local/bin/perl doesn't have permissions of 755, please correct so that awstats can run.\033[0m"
		fi

	# If /usr/local/bin/perl is a link, and /usr/bin/perl is a file, then
	elif [[ -L '/usr/local/bin/perl' ]] && [[ -f '/usr/bin/perl' ]]; then
		check=$(find '/usr/bin/perl' -perm 0755)
		if [[ -z "$check" ]]; then
			printf "%b\n" && printf "%b\n" "\033[1;31m/usr/bin/perl doesn't have permissions of 755, please correct so that awstats canl run.\033[0m"
		fi

	# If both /usr/bin/perl and /usr/local/bin/perl are symlinks, then
	elif [[ -L '/usr/bin/perl' ]] && [[ -L '/usr/local/bin/perl' ]]; then
		printf "%b\n" && printf "%b\n" "\033[1;31m*** /usr/bin/perl and /usr/local/bin/perl point to each other, there is NO working Perl on this system. ***\033[0m"
		printf "%b\n" "\033[1;31m*** You will need to reinstall the Perl RPM and then install cPanel Perl ***\033[0m"
fi
}

HttpdConf() {
# No stats if Apache conf has problems, so check syntax.
check=$(/usr/local/apache/bin/apachectl configtest 2>&1)
if [[ "$check" =~ "Syntax OK" ]]; then
	printf "%b\n" "\033[0;32mSyntax OK\033[0m"
else
	printf "%b\n" "\033[1;31mSyntax Errors \033[0m(Run: httpd configtest)"
	printf "%s\n"
	printf "%b\n" "\033[1;31m*** This means that Apache can't do a graceful restart and that the domlogs will be 0 bytes in size, so therefore no new stats will be processed until httpd.conf is fixed! ***\033[0m"
fi
}

WhoCanPick() {
# Display users who have been specified to choose stats programs
if [[ "$stats_fh" ]]; then
	users=$(echo "$stats_fh" | grep "VALIDUSERS=")
    users=${users#*=}
	if [[ -z "$users" ]]; then
		printf "%b\n" "\033[0;32mNobody\033[0m"
	else
		printf "%b\n" "\033[0;32m$users\033[0m"
	fi
	if [[ "$users" ]]; then
		check=$(find '/etc/stats.conf' -perm 644)
		if [[ -z "$check" ]]; then
			printf "%b\n"
			printf "%b\n" "\033[1;31m*** /etc/stats.conf doesn't have permissions of 644. This will cause users to not be able to choose log programs in cPanel. ***\033[0m"
			printf "\n"
			fi
	fi
else
	printf "%b\n" "\033[0;32mNobody\033[0m"
fi
}

GetEnabledDoms() {
prog=$(echo ${1} | tr "[:lower:]" "[:upper:]")
user=$2
homedir=$(grep $user /etc/passwd | cut -d: -f6 | egrep $user$)
alldoms=( $(egrep "^DNS[0-9]{0,3}=" /var/cpanel/users/${user} | sed 's/DNS[0-9]\{0,3\}=//'))
if [[ -f "$homedir/tmp/stats.conf" ]]; then
	for i in "${alldoms[@]}"; do
		capsdom=$(echo $i | tr "[:lower:]" "[:upper:]")
		domsetting=$(grep "${prog}-${capsdom}=" ${homedir}/tmp/stats.conf | sed 's/'${prog}'-//' | tr "[:upper:]" "[:lower:]")
		if [[ -z "$domsetting" ]]; then
			printf "%b\n" "$i=\033[1;31mno\033[0m"
		else
			domsetting=${domsetting/=yes/=\\033[0;32myes\\033[0m}
			domsetting=${domsetting/=no/=\\033[1;31mno\\033[0m}
			printf "%b\n" $domsetting
		fi
	done
else
	# If the user is new or just hasn't saved their log program choices in cPanel, and the stats program is active 
	# by default, then show Yes for each domain as the default then would be On since the user hasn't overridden it in cPanel.
	# If however the stats program is not active by default then show No as stats won't generate for that program unless
	# the user specifically enables it in cPanel.
	if ([[ $(UserAllowedRegex "$user") =~ "Yes" ]] || [[ $(AllAllowed) =~ "Yes" ]]) && [[ $(IsDefaultOn "$prog") =~ "On" ]]; then		
		for i in "${alldoms[@]}"; do
			printf "%b\n" "$i=\\033[0;32myes\\033[0m"
		done
	else	
		for i in "${alldoms[@]}"; do
			printf "%b\n" "$i=\033[1;31mno\033[0m"
		done
	fi
fi
}

DumpDomainConfig() {
prog=$1
user=$2
doms=$(GetEnabledDoms "$prog" "$user")
if [[ -z "$doms" ]]; then
	printf "%b\n" "\033[1;31mNO DOMAINS\033[0m :: $prog is available, but not active by default. $user \033[0;32mDOES\033[0m have own privs to enable $prog for domains, but hasn't"
else
	printf "%b\n" "\033[0;32mCAN PICK\033[0m (Per-Domain Config Listed Below)"
	domarray=($doms)
	for i in "${domarray[@]}"; do
		printf "%b\n" "  $i"
	done
fi
}

IsBlocked() {
prog=$1
user=$2

# This first looks to see if STATGENS exists in the user file.
# If it does then this means an admin override for the user in WHM
# Then see if that line contains the stats program being passed to the function. 
# If it does contain the stats program then that means that program was blocked for that user in WHM at:
# Main >> Server Configuration >> Statistics Software Configuration >> User Permissions >> Choose Users >> Choose Specific Stats Programs for
statprog=$(grep STATGENS /var/cpanel/users/$user | sed 's/.*=//' | tr '[:upper:]' '[:lower:]')
if [[ -n "$statprog" ]] && [[ $statprog != *$prog* ]]; then
	printf "%b\n" "\033[1;31mBlocked\033[0m"
	touch "/tmp/blockedprog"
fi
}

WillRunForUser() {
prog=$1
user=$2
# If the stats prog is not set as available in WHM
if [[ $(IsAvailable "$prog") =~ Disabled ]]; then
	printf "%b\n" "\033[1;31mNO DOMAINS\033[0m :: $prog is disabled server wide"
# elise, if the stats prog is blocked by the admin
elif [[ $(IsBlocked "$prog" "$user") =~ Blocked ]]; then
	printf "%b\n" "\033[1;31mBLOCKED\033[0m :: $prog is blocked by the administrator for this user"
else
	# if the prog is off then
	if [[ $(IsDefaultOn "$prog") =~ Off ]]; then
		echo $(IsDefaultOn "$prog")
		# if the "Allow all users to change their web statistics generating software." is off, then
		if [[ $(AllAllowed) =~ No ]]; then
			# if the user is added to the list to choose progs, then
			if [[ $(UserAllowedRegex "$user") =~ Yes ]]; then
					DumpDomainConfig "$prog" "$user"
			else
				# but if not, then print that prog is available but not active by default and user does not have privs to enable prog.
				printf "%b\n" "\033[1;31mNO DOMAINS\033[0m :: $prog is available, but not active by default."
				printf "\t %b\n" "$user \033[1;31mDOES NOT\033[0m have privs to enable $prog for domains"
			fi
		else
			# else, if the user can choose progs, show if prog is active or not for each domain
				DumpDomainConfig "$prog" "$user"
			fi
	else
		# if the allow all users to change stats is yes OR the user is in the allowed list, then show if prog is active or not for each domain.
		if [[ $(UserAllowedRegex "$user") =~ Yes ]] || [[ $(AllAllowed) =~ Yes ]]; then
			DumpDomainConfig "$prog" "$user"
		else
			# else, print that prog is active by default for all domains as the user has no ability to choose log progs
			printf "%b\n" "\033[0;32mALL DOMAINS\033[0m :: $prog is enabled and active by default"
		fi
	fi
fi
}

CanRunLogaholic() {
# Check if cPanel is >= 11.31 (when Logaholic was added).
version=$(echo "$cpversion_fh" | cut -f1,2 -d. | sed 's/\.//g')

if [[ $version -ge 1131 ]]; then
	printf "%b\n" "Yes"
else
		printf "%b\n" "No"
fi
}

DomainResolves() {
# Check to see if user's domains resolve to IPs bound on the server. This doesn't run if --noquery is used.
printf "%b" "ALL DOMAINS RESOLVE TO SERVER: "
user=$1
# Grab domain list from the cPanel user file
domlist=($(grep ^DNS /var/cpanel/users/$user | cut -f2 -d=))
# For each domain in the list we see if google's public DNS can resolve the IP
for i in ${domlist[*]}; do 
	ip=$(dig @8.8.8.8 +short $i)
	bound=$(/sbin/ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1}')
	# If it can't be resolved..
	if [[ -z "$ip" ]]; then 
		donotresolve="$donotresolve $i\n"
	# Else if the DNS lookup times out...
	elif [[ $ip =~ "connection timed out" ]]; then
		timedout="$timedout $i\n"
	# Else if the domain does resolve, just not to an IP on this server..
	elif ! [[ $bound =~ "$ip" ]]; then 
		notbound="$notbound $i\n"
	fi
done

# If $donotresolve and $notbound and $timedout are null, meaning all lookups were successful
if [[ -z "$donotresolve" ]] && [[ -z "$notbound" ]] && [[ -z "$timedout" ]]; then
	printf "%b\n" "\033[0;32mYES\033[0m"
else
	# Otherwise, if one or the other is not null..
	if [[ -n "$donotresolve" ]] || [[ -n "$notbound" ]] || [[ -n "$timedout" ]]; then
		printf "%b\n" "\033[1;31mNO\033[0m"
	fi

	if [[ -n "$donotresolve" ]]; then
		printf "%b\n" "The following domains do not resolve at all:"
		printf "%b\n" "\033[1;31m$donotresolve\033[0m"
	fi
	if [[ -n "$timedout" ]]; then
		printf "%b\n" "Lookups for the following domains timed out:"
		printf "%b\n" "\033[1;31m$timedout\033[0m"
	fi
	if [[ -n "$notbound" ]]; then
		printf "%b\n" "The following domains do not point to an IP bound on this server:"
		printf "%b\n" "\033[1;31m$notbound\033[0m"
	fi
fi
}

#####################
# Main Blob of Code #
#####################

# Run the Awwwstats function to see if awstats.pl is executable, and run CheckPerl to verify Perl configuration
Awwwwstats 
#CheckPerl

# No arg = general info on web stats setup
if [ -z "$user" ]; then
	printf "\n"
	printf "%s\n" "Displaying general information on web stats configuration."
	printf "%s\n" "To display user configuration, run \"webstatsprobe <cP User>\""
	printf "\n"	
	printf "%b\n" "\033[0;36m[ Web Stats Probe v"$version" - Results For: \033[1;33mSystem\033[0;36m ]\033[0m"
	printf "\n"	
	printf "%b\n" "CPANELLOGD: $(LogDRunning)"
	printf "%b\n" "HTTPD CONF: $(HttpdConf)"
	printf "%b\n" "BLACKED OUT: $(BlackedHours)"
	printf "%b\n" "LOG PROCESSING RUNS EVERY: \033[;32m$(LogsRunEvery) hours \033[0m"
	printf "%b\n" "BANDWITH PROCESSING RUNS EVERY: \033[;32m$(BandwidthRunsEvery) hours \033[0m"
	printf "%b\n" "KEEPING UP: $(KeepingUp)"
	printf "%b\n" "CAN ALL USERS PICK: $(AllAllowed)"
	if [[ $(AllAllowed) =~ No ]]; then
			printf "%b\n" "WHO CAN PICK STATS: $(WhoCanPick)"
	fi
	printf "%b\n" "ANALOG: $(IsAvailable "analog") (Active by Default: $(IsDefaultOn "ANALOG"))"
	printf "%b\n" "AWSTATS: $(IsAvailable "awstats") (Active by Default: $(IsDefaultOn "AWSTATS"))"
	printf "%b\n" "WEBALIZER: $(IsAvailable "webalizer") (Active by Default: $(IsDefaultOn "WEBALIZER"))"
	if [[ $(CanRunLogaholic) =~ Yes ]]; then
		printf "%b\n" "LOGAHOLIC: $(IsAvailable "logaholic") (Active by Default: $(IsDefaultOn "LOGAHOLIC"))"
	fi
else
	# If called with a user argument, let's verify that user exists and display the output
	if [[ -f "/var/cpanel/users/$user" ]] && [[ -d "/var/cpanel/userdata/$user" ]]; then
		printf "\n"	
		printf "%s\n" "Available flags when running 'webstatsprobe <user>'"
		if ! [[ "$@" =~ --noquery ]]; then
			printf "%s\n" "--noquery (turns off DNS lookups for each user domain)"
		else
			printf "%s\n" "None"
		fi
		
		printf "\n"
		printf "%b\n" "\033[0;36m[ Web Stats Probe v"$version" - Results For: \033[1;33m$user\033[0;36m ]\033[0m"
		printf "\n"
		# Here we want to test and see if STATGENS is present in the cPanel user file.
		# If it is this means that the server admin has blocked out certain stats
		# applications for the specific users in WHM. If STATGENS exists then we test to see if
		# there are any stats programs listed after STATGENS=. If not then the admin has blocked
		# all stats programs. Yes, we have seen someone do this before.
		if [[ $(grep STATGENS /var/cpanel/users/$user) ]] && [[ -z $(grep STATGENS /var/cpanel/users/$user | sed 's/.*=//') ]]; then
			printf "%b\n" "\033[1;31m*** ALL STATS PROGRAMS BLOCKED FOR USER BY SERVER ADMIN IN WHM ***\033[0m"
		fi
		# Check if each of the user domains resolve to IP on the server
		if [[ "$noquery" -ne 1 ]]; then
			DomainResolves $user
		fi
			printf "%b\n" "KEEPING UP (STATS): $(UserKeepUp "$user") (Last Run: $(LastRun "$user"))"
			printf "%b\n" "KEEPING UP (BANDWIDTH): $(BwUserKeepUp "$user") (Last Run: $(BwLastRun "$user"))"
		if [[ $(BwUserKeepUp "$user") =~ No ]]; then 
			printf "\n"
			printf "%b\n" "\033[1;31m*** Bandwidth processing isn't keeping up! Please check the eximstats DB for corruption***\033[0m"
			printf "%b\n" "If the eximstats.sends table is corrupted then when runweblogs is ran the smtp rrd file won't generate correctly and the file /var/cpanel/lastrun/$user/bandwidth won't update."
			printf "%b\n" "\033[1;31m*** Please run: \"mysqlcheck -r eximstats\" ***\033[0m"
			printf "\n"
		fi
			printf "%b\n" "ANALOG: $(WillRunForUser "analog" "$user")"
			printf "%b\n" "AWSTATS: $(WillRunForUser "awstats" "$user")"
			printf "%b\n" "WEBALIZER: $(WillRunForUser "webalizer" "$user")"
			if [[ $(CanRunLogaholic) =~ Yes ]]; then
			printf "%b\n" "LOGAHOLIC: $(WillRunForUser "logaholic" "$user")"
			fi
		if [[ $(AllAllowed) =~ No ]] && [[ $(UserAllowedRegex "$user") = No ]] ; then
		printf "%b\n" "CAN PICK STATS: $(UserAllowed "$user")"
		fi
		if [[ -e '/tmp/blockedprog' ]]; then
			printf "\n"
			printf "%b\n" "\033[1;31m*** Webstatsprobe reports that one or more statsprograms are BLOCKED for the user by the server admin. ***\033[0m"
			printf "%b\n" "\033[1;31mTo correct this issue in WHM, go to:\033[0m"
			printf "%s\n" "Server Configuration >> Statistics Software Configuration >> User Permissions >>"
			printf "%s\n" "Choose Users >> Choose Specific Stats Programs for"
			printf "\n"
			printf "%s\n" "To use the default setting of all apps available, remove the STATGENS line from the cPanel user file."
			rm -f '/tmp/blockedprog'
		fi
	else
		# Otherwise we say too bad so sad. 
		printf "\n"
			printf "%b\n" "ERROR: User [ $user ] not found."
		printf "%b\n" "You may have entered the wrong username, or /var/cpanel/$user or /var/cpanel/userdata/$user is missing."
			printf "%b\n" "Usage: $0 <cP User>"
	fi
fi
printf "\n"
