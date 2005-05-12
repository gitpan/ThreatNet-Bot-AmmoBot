use inc::Module::Install;

name          ( 'ThreatNet-Bot-AmmoBot'               );
abstract      ( 'Tail threat messages from a file to ThreatNet' );
author        ( 'Adam Kennedy <cpan@ali.as>'          );
version_from  ( 'lib/ThreatNet/Bot/AmmoBot.pm'        );
license       ( 'perl'                                );

requires      ( 'perl'                     => '5.005' );
requires      ( 'Params::Util'             => '0.01'  );
requires      ( 'Getopt::Long'             => 0       );
requires      ( 'POE'                      => 0       );
requires      ( 'POE::Wheel::FollowTail'   => 0       );
requires      ( 'POE::Component::IRC'      => 0       );
requires      ( 'ThreatNet::Message::IPv4' => '0.01'  );
requires      ( 'ThreatNet::Filter'        => '0.02'  );

build_requires( 'Test::More'               => '0.47'  );
build_requires( 'File::Spec'               => '0.82'  );

auto_install();

&WriteAll;
