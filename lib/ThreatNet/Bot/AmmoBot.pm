package ThreatNet::Bot::AmmoBot;

=pod

=head1 NAME

ThreatNet::Bot::AmmoBot - Tail threat messages from a file to ThreatNet

=head1 SYNOPIS

  # Tail ThreatNet-compatible messages from a file to IRC
  > ./ammobot --nick=ammobot            \
  >           --server=irc.freenode.org \
  >           --channel=#threatnet      \
  >           --port=6669               \
  >           --file=/var/log/threats.log

=head1 DESCRIPTION

C<ammobot> is the basic foot soldier of the ThreatNet bot ecosystem,
fetching ammunition and bringing it to the channel.

It connects to a single ThreatNet channel, and then tails a file scanning
for threat messages while following the basic channel rules.

When it sees a L<ThreatNet::Message::IPv4>-compatible message appear
at the end of the file, it will report it to the channel (subject to
the appropriate channel rules).

Its main purpose is to make it as easy as possible to connect any system
capable of writing a log file to ThreatNet. If an application can be
configured or coded to spit out the appropriately formatted messages to
a file, then C<ammobot> will patiently watch for them and then haul them
off to the channel for you (so you don't have to).

=head1 METHODS

=cut

use strict;
use warnings;
use Params::Util '_INSTANCE';
use POE qw(Wheel::FollowTail);
use ThreatNet::Message::IPv4       ();
use ThreatNet::Filter::Chain       ();
use ThreatNet::Filter::Network     ();
use ThreatNet::Filter::ThreatCache ();

use vars qw{$VERSION};
BEGIN {
	$VERSION = '0.01';
}





#####################################################################
# Constructor and Start/Stop

=pod

=head2 spawn %args

The isn't really any big reason that you would be wanting to instantiate
a C<ThreatNet::Bot::AmmoBot> yourself, but if it comes to that you do
it by simply passing a list of the appropriate arguments to the C<spawn>
method.

Because C<ammobot> is POE based, C<spawn> behaves like your typical POE
component.

  # Create the ammobot
  my $Bot = ThreatNet::Bot::AmmoBot->spawn( %args );
  
  # Run the ammobot
  POE::Kernel->run;

=cut

sub spawn {
	my ($class, %args) = @_;

	# Check the args
	$args{Nick}     or die "Did not specify a nickname";
	$args{Channel}  or die "Did not specify a channel";
	$args{Channel} =~ /^\#\w+$/
			or die "Invalid channel specification";
	$args{Server}   or die "Did not specify a server";
	$args{Port}     ||= 6669;
	$args{Username} ||= $args{Nick};
	$args{Ircname}  ||= $args{Nick};
	$args{File}     or die "Did not specify a file to tail";
	-f $args{File}  and
	-r $args{File}  or die "No permissions to read '$args{File}'";

	# Create the IRC client
	unless ( _INSTANCE($args{IRC}, 'POE::Component::IRC') ) {
		$args{IRC} = POE::Component::IRC->spawn
			or die "Failed to create new IRC server: $!";
	}

	# Create the main Bot session
	POE::Session->create(
		inline_states => {
			_start           => \&_start,
			stop             => \&_stop,

			tail_input       => \&_tail_input,
			tail_error       => \&_tail_error,

			irc_001          => \&_irc_001,
			irc_socketerr    => \&_irc_socketerr,
			irc_disconnected => \&_irc_disconnected,
			irc_public       => \&_irc_public,

			threat_recieve   => \&_threat_recieve,
			threat_send      => \&_threat_send,
		},
		args => [ \%args ],
	);
}

# Called when the Kernel fires up
sub _start {
	%{$_[HEAP]} = %{$_[ARG0]};

	# Create the main message i/o filter
	$_[HEAP]->{Filter} = ThreatNet::Filter::Chain->new(
		ThreatNet::Filter::Network->new( discard => 'rfc3330' ),
		ThreatNet::Filter::ThreatCache->new,
		) or die "Failed to create Message I/O Filter";

	# Register for events and connect to the server
	$_[HEAP]->{IRC}->yield( register => 'all' );
	$_[HEAP]->{IRC}->yield( connect  => {
		Nick     => $_[HEAP]->{Nick},
		Server   => $_[HEAP]->{Server},
		Port     => $_[HEAP]->{Port},
		Username => $_[HEAP]->{Username},
		Ircname  => $_[HEAP]->{Ircname},
		} );

	# Create the file tail
	$_[HEAP]->{Tail} = POE::Wheel::FollowTail->new(
		Filename     => $_[HEAP]->{File},
		PollInterval => 1,
		InputEvent   => 'tail_input',
		ErrorEvent   => 'tail_error',
		);
}

sub _stop {
	# Stop tailing the file (by deleting it apparently)
	delete $_[HEAP]->{Tail};

	# Disconnect from IRC
	if ( $_[HEAP]->{IRC} ) {
		if ( $_[HEAP]->{IRC}->connected ) {
			$_[HEAP]->{IRC}->yield( quit => 'Controlled shutdown' );
		}
		delete $_[HEAP]->{IRC};
	}

	1;
}





#####################################################################
# The Tailing of the File

sub _tail_input {
	my $input = $_[ARG0];
	chomp $input;

	# Does the input line form a valid message?
	my $Message = ThreatNet::Message::IPv4->new( $input ) or return;

	# Send the Message to the channel (or not, for now)
	$_[KERNEL]->yield( threat_send => $Message );
}

sub _tail_error {
	$_[KERNEL]->yield( stop => 1 );
}





#####################################################################
# IRC Events

# Connected
sub _irc_001 {
	$_[HEAP]->{IRC}->yield( join => $_[HEAP]->{Channel} );
}

# Failed to connect
sub _irc_socketerr {
	$_[KERNEL]->yield( stop => 1 );
}

# We were disconnected
### FIXME - Make this reconnect
sub _irc_disconnected {
	if ( $_[HEAP]->{IRC} ) {
		$_[KERNEL]->yield( stop => 1 );
	} else {
		# Already shutting down, do nothing
	}
}

# Normal channel message
sub _irc_public {
	my ($who, $where, $msg) = @_[ARG0, ARG1, ARG2];

	# Is this a ThreatNet message?
	my $Message = ThreatNet::Message::IPv4->new($msg) or return;

	# Pass the message through the channel i/o filter
	$_[HEAP]->{Filter}->keep($Message) or return;

	# Hand off to the threat_recieve message
	$_[KERNEL]->yield( threat_recieve => $Message );
}





#####################################################################
# ThreatNet Events

# We just do nothing normally
sub _threat_recieve {
	1;
}

sub _threat_send {
	my $Message = $_[ARG0];

	# Pass it through the filter
	$_[HEAP]->{Filter}->keep($Message) or return;

	# Send the message immediately
	$_[HEAP]->{IRC}->yield( privmsg => $_[HEAP]->{args}->{Channel}, $Message->message );
}

1;

=pod

=head1 TO DO

- Add support for multiple files

- Add support for custom file format specifications

- Add support for additional outbound filters

=head1 SUPPORT

All bugs should be filed via the bug tracker at

L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=ThreatNet-Bot-AmmoBot>

For other issues, or commercial enhancement and support, contact the author

=head1 AUTHORS

Adam Kennedy (Maintainer), L<http://ali.as/>, cpan@ali.as

=head1 SEE ALSO

L<http://ali.as/devel/threatnetwork.html>, L<POE>

=head1 COPYRIGHT

Copyright (c) 2005 Adam Kennedy. All rights reserved.
This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=cut
