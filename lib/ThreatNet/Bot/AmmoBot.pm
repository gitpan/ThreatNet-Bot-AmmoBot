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
use POE qw(
	Wheel::FollowTail
	Component::IRC
	);
use ThreatNet::Message::IPv4       ();
use ThreatNet::Filter::Chain       ();
use ThreatNet::Filter::Network     ();
use ThreatNet::Filter::ThreatCache ();

use vars qw{$VERSION};
BEGIN {
	$VERSION = '0.03';
}





#####################################################################
# Constructor and Accessors

=pod

=head2 new %args

The isn't really any big reason that you would be wanting to instantiate
a C<ThreatNet::Bot::AmmoBot> yourself, but if it comes to that you do
it by simply passing a list of the appropriate arguments to the C<new>
method.

  # Create the ammobot
  my $Bot = ThreatNet::Bot::AmmoBot->new( %args );
  
  # Run the ammobot
  $Bot->run;

=cut

sub new {
	my ($class, %args) = @_;

	# Check the args
	$args{Nick}     or die "Did not specify a nickname";
	$args{Channel}  or die "Did not specify a channel";
	$args{Channel} =~ /^\#\w+$/
			or die "Invalid channel specification";
	$args{Server}   or die "Did not specify a server";
	$args{Port}     ||= 6667;
	$args{Username} ||= $args{Nick};
	$args{Ircname}  ||= $args{Nick};
	$args{Tails}    = {};

	# Create the IRC client
	unless ( _INSTANCE($args{IRC}, 'POE::Component::IRC') ) {
		$args{IRC} = POE::Component::IRC->spawn
			or die "Failed to create new IRC server: $!";
	}

	# Create the empty object
	my $self = bless {
		running => '',
		args    => \%args,
		}, $class;

	$self;
}

sub args    { $_[0]->{args}          }
sub tails   { $_[0]->{args}->{Tails} }
sub running { $_[0]->{running}       }
sub Session { $_[0]->{Session}       }

sub files {
	my $self = shift;
	wantarray
		? (sort keys %{$self->tails})
		: scalar(keys %{$self->tails});
}





#####################################################################

# Add a file to the bot
sub add_file {
	my $self = shift;
	$self->running and die "Cannot add files once the bot is running";
	my $file = ($_[0] and -f $_[0] and -r $_[0]) ? shift
		: die "Invalid file '$_[0]'";
	if ( $self->tails->{$file} ) {
		die "File '$file' already attached to bot";
	}

	# Create the basic FollowTail params
	my %args = @_;
	my %Params = (
		Filename     => $file,
		PollInterval => 1,
		InputEvent   => 'tail_input',
		ErrorEvent   => 'tail_error',
		);

	# Add the optional params if needed
	if ( _INSTANCE($args{Driver}, 'POE::Driver') ) {
		$Params{Driver} = $args{Driver};
	} elsif ( $args{Driver} ) {
		die "Driver param was not a valid POE::Driver";
	}
	if ( _INSTANCE($args{Filter}, 'POE::Filter') ) {
		$Params{Filter} = $args{Filter};
	} elsif ( $args{Filter} ) {
		die "Filter param was not a valid POE::Filter";
	}

	# Save the FollowTail params
	$self->tails->{$file} = \%Params;

	1;
}

sub run {
	my $self = shift;
	unless ( $self->files ) {
		die "Refusing to start, no files added";
	}

	# Create the Session
	$self->{Session} = POE::Session->create(
		inline_states => {
			_start           => \&_start,
			stop             => \&_stop,

			tail_input       => \&_tail_input,
			tail_error       => \&_tail_error,

			irc_001          => \&_irc_001,
			irc_socketerr    => \&_irc_socketerr,
			irc_disconnected => \&_irc_disconnected,
			irc_public       => \&_irc_public,

			threat_receive   => \&_threat_receive,
			threat_send      => \&_threat_send,
			},
		args => [ $self->args ],
		);

	$self->{running} = 1;
	POE::Kernel->run;
}





#####################################################################
# POE Event Handlers

# Add a file
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

	# Initialize the tails
	my $Tails = $_[HEAP]->{Tails};
	foreach my $key ( sort keys %$Tails ) {
		$Tails->{$key} = POE::Wheel::FollowTail->new( %{$Tails->{$key}} )
			or die "Failed to create FollowTail for $key";
	}
}

sub _stop {
	# Stop tailing the files
	delete $_[HEAP]->{Tails};

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

	# Hand off to the threat_receive message
	$_[KERNEL]->yield( threat_receive => $Message );
}





#####################################################################
# ThreatNet Events

# We just do nothing normally
sub _threat_receive {
	1;
}

sub _threat_send {
	my $Message = $_[ARG0];

	# Pass it through the filter
	$_[HEAP]->{Filter}->keep($Message) or return;

	# Send the message immediately
	$_[HEAP]->{IRC}->yield( privmsg => $_[HEAP]->{Channel}, $Message->message );
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
