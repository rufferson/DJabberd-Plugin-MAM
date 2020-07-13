#!/usr/bin/perl
use strict;
use Test::More tests => 3;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Authen::AllowedUsers;
use DJabberd::Authen::StaticPassword;
use DJabberd::RosterStorage::InMemoryOnly;
use DJabberd::RosterItem;

use DJabberd::Plugin::MAM::InMemoryOnly;

my $domain = "example.com";
my $dother = "example.org";

my $plugs = [
            DJabberd::Authen::AllowedUsers->new(policy => "deny",
                                                allowedusers => [qw(partya partyb)]),
            DJabberd::Authen::StaticPassword->new(password => "password"),
            DJabberd::RosterStorage::InMemoryOnly->new(),
	    DJabberd::Plugin::MAM::InMemoryOnly->new(),
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
my $sub = DJabberd::Subscription->new();
my $ri = DJabberd::RosterItem->new( jid => $her, subscription => $sub);

sub disco {
    $vhost->run_hook_chain(
	phase=> "DiscoBare",
	args     => [ 'iq', 'info', $my, $her, $ri ],
	methods => {
	    addFeatures => sub {
		my $cb = shift;
		for my $ns (@_) {
		    if(!ref($ns)) {
			if($ns eq DJabberd::Plugin::MAM::NSMAM0 ||
			    $ns eq DJabberd::Plugin::MAM::NSMAM1 ||
			    $ns eq DJabberd::Plugin::MAM::NSMAM2)
			{
			    ok(1, $ns);
			}
		    }
		}
		$cb->reset;
		$cb->decline;
	    },
	}
    );
}
disco();
$sub->set_from(1);
disco();
