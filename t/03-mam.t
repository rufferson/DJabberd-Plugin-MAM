#!/usr/bin/perl
use strict;
use Test::More tests => 30;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Authen::AllowedUsers;
use DJabberd::Authen::StaticPassword;
use DJabberd::RosterStorage::InMemoryOnly;
use Time::HiRes qw/CLOCK_REALTIME/;
use POSIX qw(strftime);

use DJabberd::Plugin::Carbons;
use DJabberd::Delivery::OfflineStorage;
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
my @ids=map{"mamoid$_"}(1..5);

# Add some message
my $msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}from' => $my,
	'{}to' => $her,
	'{}id' => 'mamoid1',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[],'Hola!'),
    ]);
##
# Sanity check - by default message should not be stored as the default='never'
$msg->deliver($vhost);
ok(scalar(@{$mam->{__store}{ring}}) == 0, 'Has 0 messages');


##
# Change the default to 'always' and ensure all messages are stored
$mam->set_config_default('always');
$msg->deliver($vhost);
$msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}from' => $my,
	'{}to' => $her,
	'{}id' => 'mamoid2',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[], "¿Cómo está?"),
    ]);
$msg->deliver($vhost);
$msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}from' => $her,
	'{}to' => $my,
	'{}id' => 'mamoid3',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[], "Hola! Bien! фыčí"),
    ]);
$msg->deliver($vhost);
##
# Must be 3 of them by now
ok(scalar(@{$mam->{__store}{ring}}) == 3, 'Has 3 messages');
# remember this very moment
my $ts = Time::HiRes::clock_gettime(CLOCK_REALTIME);

my $test = sub {
    my $x = $_[0];
    if($x =~ /^<message/) {
	ok($x =~ /<result[^>]+queryid=['"]mamq1['"][^<]+<forwarded/, $x);
    } elsif($x =~ /^<iq/) {
	ok($x =~ /^<iq[^>]+type=['"]result['"]/, $x)
    }
};
my $err_ok = sub { ok($_[0] =~ /^<iq[^>]+type=['"]error['"]/, $_[0]) };

my $query = DJabberd::XMLElement->new(DJabberd::Plugin::MAM::NSMAM2, 'query',
    {
	xmlns => DJabberd::Plugin::MAM::NSMAM2,
	'{}queryid' => 'mamq1',
    },
    [
    ]);
my $iq = DJabberd::IQ->new('jabber:client', 'iq',
    {
	xmlns=> 'jabber:client',
	'{}type' => 'set',
	'{}from' => $my,
	'{}to' => $my,
	'{}id' => 'iq1',
    },
    [ $query ]);
my $fc = FakeCon->new($vhost, DJabberd::JID->new($my), sub { $test->(${$_[1]}) }, \&check_xml, sub{ok(check_msg(@_),$_[0]->as_xml)});
$iq->set_connection($fc);

# Query the archive with defaults - 4 ok
$iq->process($fc);

# Query other's archive - 1 ok
$test = $err_ok;
$iq->set_to('partyb@'.$domain);
$iq->process($fc);

my $h=DJabberd::SAXHandler->new;
my $p=DJabberd::XMLParser->new(Handler => $h);
$p->parse_chunk("<stream:stream xmlns:stream='jabber:client'>");
$h->set_connection($fc);

my $mcheck = sub {
    my $x = shift;
    my $oid = $x->attr('{}id');
    my ($id) = grep{$_ eq $oid}@ids;
    return $id;
};
$test = sub { eval { $p->parse_chunk(@_) } or fail($@.': '.$_[0] )};
##
# Detailed query check - 4 ok with schema checks
my $check_rsm = sub {
    my $fin = shift;
    my ($first) = grep{$_->element_name eq 'first'}@_;
    my ($last) = grep{$_->element_name eq 'last'}@_;
    if($first && $first->children && $last && $last->children) {
	ok($fin->attr('{}complete') eq 'true' && $first->attr('{}index') eq '0', join('',map{$_->as_xml}@_));
	return 1;
    }
    return -1;
};
$iq->set_to(undef);
$iq->process($fc);

##
# Detailed RSM check - 5 ok (2+1 + 1+1)
my $rsm = DJabberd::XMLElement->new('http://jabber.org/protocol/rsm', 'set',
    { xmlns=>'http://jabber.org/protocol/rsm' },
    [ DJabberd::XMLElement->new(undef,'max',{},['2']) ],
);
my $next;
$query->push_child($rsm);
$check_rsm = sub {
    my $fin = shift;
    my ($first) = grep{$_->element_name eq 'first'}@_;
    my ($last) = grep{$_->element_name eq 'last'}@_;
    if($first && $first->children && $last && $last->children) {
	if($fin->attr('{}complete') eq 'true') {
	    ok($first->attr('{}index') eq '0', join('',map{$_->as_xml}@_));
	} else {
	    $next = $last->first_child;
	    ok($next, join('',map{$_->as_xml}@_));
	}
	return 1;
    }
};
$iq->process($fc);
# Get next page
if($next) {
    my $after = DJabberd::XMLElement->new(undef,'after',{},[$next]);
    $rsm->push_child($after);
    $iq->set_attr('{}id', 'iq2');
    $iq->process($fc);
    # reset the state
    $next = undef;
    $rsm->remove_child($after);
}

##
# Strictly check stanza-id stripping
my $cb = DJabberd::Callback->new({registered=>sub{}});
$vhost->register_jid(DJabberd::JID->new($my), 'test', $fc, $cb);
$msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}from' => $her,
	'{}to' => $my,
	'{}id' => 'mamoid4',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[], "¿y tú?"),
	# We also want to test SID protection (stripping)
	DJabberd::XMLElement->new('urn:xmpp:sid:0','stanza-id',{xmlns=>'urn:xmpp:sid:0', '{}id'=>'123', '{}by'=>$my}, []),
    ]);
$msg->deliver($vhost);
ok(scalar(@{$mam->{__store}{ring}}) == 4, 'Has 4 messages');

##
# Now get all pages in reverse order +6
my $before = DJabberd::XMLElement->new(undef, 'before', {}, []);
$rsm->push_child($before);
my @revids = ('mamoid3', 'mamoid4', 'mamoid1', 'mamoid2' );
my $oid = $mcheck;
$mcheck = sub {
    my $x = shift;
    my $id = $oid->($x);
    return $id eq shift(@revids);
};
$check_rsm = sub {
    my $fin = shift;
    my ($first) = grep{$_->element_name eq 'first'}@_;
    my ($last) = grep{$_->element_name eq 'last'}@_;
    if($first && $first->children && $last && $last->children) {
	if($fin->attr('{}complete') eq 'true') {
	    ok($first->attr('{}index') eq '0', join('',map{$_->as_xml}@_));
	} else {
	    $next = $first->first_child;
	    ok($next, join('',map{$_->as_xml}@_));
	}
	return 1;
    }
};
$iq->process($fc);
if($next) {
    $before->push_child($next);
    $iq->set_attr('{}id', 'iq3');
    $iq->process($fc);
    # reset the state
    $next = undef;
}
$rsm->remove_child($before);

##
# Form test - get the latest message - after timestamp $ts
my $form = DJabberd::Form->new('submit', [
	{var=>'FORM_TYPE',value=>['urn:xmpp:mam:2'], type=>'hidden'},
	{var=>'start', value=>[strftime("%Y-%m-%dT%H:%M:%S", gmtime($ts)).sprintf(".%05d",($ts-int($ts))*10**5)]},
    ]);
$form = $form->as_element();
$query->push_child($form);
@revids=('mamoid4');
$iq->process($fc);

##
# And final one - check jid filtering
$msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}from' => 't800@sky.net',
	'{}to' => $my,
	'{}id' => 'mamoid5',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[], "I need a vacation."),
	# We also want to test SID protection (stripping)
	DJabberd::XMLElement->new('urn:xmpp:sid:0','stanza-id',{xmlns=>'urn:xmpp:sid:0', '{}id'=>'123', '{}by'=>$my}, []),
    ]);
@revids=('mamoid5');
$msg->deliver($vhost);
ok(scalar(@{$mam->{__store}{ring}}) == 5, 'Has 5 messages');

my $with = DJabberd::XMLElement->new('jabber:x:data','field',
	{'{}var'=>'with'},
	[ DJabberd::XMLElement->new('jabber:x:data','value',{},['t800@sky.net']) ]);
$form->push_child($with);
@revids=('mamoid5');
$iq->process($fc);

##########################################################################
# Test processing machinery
##########################################################################
sub check_xml {
    if(my$ret = check_res(@_)) {
	return fail($_[0]->innards_as_xml) if($ret<0);
	return;
    }
    if(my$ret = check_iq(@_)) {
	return fail($_[0]->innards_as_xml) if($ret<0);
	return;
    }
    fail($_[0]->as_xml);
}

sub check_msg {
    my $x = shift;
    if($x->element_name eq 'message') {
	my ($sid) = grep{$_->element eq '{urn:xmpp:sid:0}stanza-id'}$x->children_elements;
	my $storable = DJabberd::Plugin::Carbons::eligible($x, 313);
	my $forged = (($sid && $sid->attr('{}id') eq '123') || '');
	my $custo = ref($mcheck) ? $mcheck->($x) : 'n/a';
	if($storable && !$forged && $custo) {
	    return 1;
	} else {
	    print STDERR "Storable: $storable; Forged: $forged; Custom: $custo\n";
	    print STDERR $x->as_xml."\n";
	}
    }
    return 0;
}
sub check_res {
    my $x = shift;
    if($x->element_name eq 'message') {
	my $r = $x->first_element;
	if($r->element eq '{urn:xmpp:mam:2}result' && $r->attr('{}queryid') eq 'mamq1' && $r->attr('{}id') ne '123') {
	    my $f = $r->first_element;
	    if($f->element eq '{urn:xmpp:forward:0}forwarded') {
		my ($d) = grep{$_->element eq '{urn:xmpp:delay}delay'}$f->children_elements;
		my ($m) = grep{$_->element eq '{jabber:client}message'}$f->children_elements;
		if($d && $d->attr('{}stamp') && $m) {
		    ok(check_msg($m), $m->innards_as_xml);
		    return 1;
		}
	    }
	}
	return -1;
    }
    return 0;
}

sub check_iq {
    my $x = shift;
    if($x->element_name eq 'iq') {
	my $f = $x->first_element;
	if($x->attr('{}type') eq 'result' && $f->element eq '{urn:xmpp:mam:2}fin' && $f->children_elements) {
	    my ($r) = grep{$_->element eq '{http://jabber.org/protocol/rsm}set'}$f->children_elements;
	    if($r && $r->children_elements) {
		return $check_rsm->($f, $r->children_elements);
	    }
	}
	return -1;
    }
    return 0;
}

package FakeCon;

sub new {
    bless { vh=>$_[1], jid=>$_[2], wr=>$_[3], sr=>$_[4], ss=>$_[5],
	xl=>DJabberd::Log->get_logger('FakeCon::XML'), in_stream => 1}, $_[0];
}

sub is_server { 0 }
sub is_available { 1 }
sub vhost { $_[0]->{vh} }
sub bound_jid { $_[0]->{jid} }
sub xmllog { $_[0]->{xl} }
sub write { $_[0]->{wr}->(@_) }
sub log_outgoing_data { $_[0]->{xl}->debug($_[1]) }
sub on_stanza_received { $_[0]->{sr}->($_[1]) }
sub send_stanza { $_[0]->{ss}->($_[1]) }

