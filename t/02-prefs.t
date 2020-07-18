#!/usr/bin/perl
use strict;
use Test::More tests => 8;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Authen::AllowedUsers;
use DJabberd::Authen::StaticPassword;
use DJabberd::RosterStorage::InMemoryOnly;

use DJabberd::Plugin::MAM::InMemoryOnly;

my $domain = "example.com";
my $dother = "example.org";

my $mam = DJabberd::Plugin::MAM::InMemoryOnly->new();
$mam->finalize();

my $plugs = [
            DJabberd::Authen::AllowedUsers->new(policy => "deny",
                                                allowedusers => [qw(partya partyb)]),
            DJabberd::Authen::StaticPassword->new(password => "password"),
            DJabberd::RosterStorage::InMemoryOnly->new(),
	    $mam,
            DJabberd::Delivery::Local->new,
            DJabberd::Delivery::S2S->new
	];
my $vhost = DJabberd::VHost->new(
            server_name => $domain,
            s2s         => 1,
            plugins     => $plugs,
        );

my ($me, $she) = ('partya', 'partyb');
my ($my, $her) = ('partya@'.$domain, 'partyb@'.$dother);

my $res_ok = sub { ok($_[0] =~ /^<iq[^>]+type=['"]result['"]/, $_[0]) };
my $err_ok = sub { ok($_[0] =~ /^<iq[^>]+type=['"]error['"]/, $_[0]) };
my $forbidden = sub { ok($_[0] =~ /<error[^<]+<forbidden/m, $_[0]) };
my $notimplemented = sub { ok($_[0] =~ /<error[^<]+<feature-not-implemented/m, $_[0]) };
my $default_always = sub { ok($_[0] =~ /<prefs[^>]+default=['"]always['"][^<]+<(always|never)[^>]+>/m, $_[0]) };
my $default_never = sub { ok($_[0] =~ /<prefs[^>]+default=['"]never['"][^<]+<(always|never)[^>]+>/m, $_[0]) };


my $test;
my $iq = DJabberd::IQ->new('jabber:client', 'iq',
    {
	xmlns=> 'jabber:client',
	'{}type' => 'get',
	'{}from' => $my,
	'{}to' => $my,
	'{}id' => 'iq1',
    },
    [
	DJabberd::XMLElement->new(DJabberd::Plugin::MAM::NSMAM2, 'prefs', { xmlns => DJabberd::Plugin::MAM::NSMAM2 }),
    ]);
my $fc = FakeCon->new($vhost, DJabberd::JID->new($my), sub { $test->(${$_[1]}) });
$iq->set_connection($fc);

# Test defaults: query own prefs, default is never
$test = $res_ok;
$iq->process($fc);
$test = $default_never;
$iq->process($fc);
# but could be configured to always
$mam->set_config_default('always');
$test = $default_always;
$iq->process($fc);

# Test access control: query other's prefs
$iq->set_to('partyb@'.$domain);
$test = $err_ok;
$iq->process($fc);
$test = $forbidden;
$iq->process($fc);

# Also check with implied own bare (no "to")
$test = $res_ok;
$iq->set_to(undef);
$iq->process($fc);

# Test pref set - currently not implemented
$iq->set_attr('{}type', 'set');
$test = $err_ok;
$iq->process($fc);
$test = $notimplemented;
$iq->process($fc);


package FakeCon;

sub new {
    bless { vh=>$_[1], jid=>$_[2], wr=>$_[3], xl=>DJabberd::Log->get_logger('FakeCon::XML')}, $_[0];
}

sub is_server { 0 }
sub vhost { $_[0]->{vh} }
sub bound_jid { $_[0]->{jid} }
sub xmllog { $_[0]->{xl} }
sub write { $_[0]->{wr}->(@_) }

