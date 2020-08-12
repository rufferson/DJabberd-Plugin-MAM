package DJabberd::Plugin::MAM;
# vim: sts=4 ai:
use warnings;
use strict;
use base 'DJabberd::Plugin';
use Time::HiRes qw (CLOCK_REALTIME);

use constant {
	NSMAM0 => "urn:xmpp:mam:0",
	NSMAM1 => "urn:xmpp:mam:1",
	NSMAM2 => "urn:xmpp:mam:2",
};

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Plugin::MAM - Implements XEP-0313 Message Archive Management

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Implements XEP-0313 Message Archive Management (MAM) - a part of XMPP Advanced IM Server compliance [2016+].

    <VHost mydomain.com>
	<Plugin DJabberd::Plugin::MAM>
	    default <always|never|roster>
	    retain <1-999>
	</Plugin>
    </VHost>


=over

=item default

Specifies default server archiving policy when user does not provide one.
Default C<default> is C<never>.

=item retain

Specifies how many days of archive to retain.
Default C<retain> is C<30> days.

=back

=cut

sub set_config_default {
    my $self = shift;
    $self->{default} = shift || 'never';
}

sub set_config_retain {
    my $self = shift;
    my $val = shift;
    if($val =~ /[0-9]+([smhDWMY])/) {
	$self->{retain_num} = 0;
	$self->{retain_sec} = $val * {s=>1,m=>60,h=>60*60,D=>60*60*24,W=>60*60*24*7,M=>60*60*24*30,Y=>60*60*24*365}->{$1};
    } elsif($val eq 'all' || $val == 0) {
	$self->{retain_num} = -1;
    } elsif($val =~ /^\d+$/) {
	$self->{retain_num} = 0 + $val;
    } else {
	$logger->error("Retain value $val is not recognizable");
    }
}

sub finalize {
    my $self = shift;
    $self->{default} ||= 'never';
    $self->{retain_sec} = 60*60*24 unless($self->{retain_num} || $self->{retain_sec});
    $self->{seqid} = int(rand(2**32));
}

sub run_before {
    return qw(DJabberd::Delivery::Local DJabberd::Plugin::Carbons);
}

sub run_after {
    return qw(DJabberd::Plugin::Privacy);
}

=head2 register($self, $vhost)

Register the vhost with the module.

=cut

my %dispatch = (
    'set-{'.NSMAM0.'}query' => \&query,
    'set-{'.NSMAM1.'}query' => \&query,
    'set-{'.NSMAM2.'}query' => \&query,
    'get-{'.NSMAM0.'}prefs' => \&prefs,
    'set-{'.NSMAM0.'}prefs' => \&prefs,
    'get-{'.NSMAM1.'}prefs' => \&prefs,
    'set-{'.NSMAM1.'}prefs' => \&prefs,
    'get-{'.NSMAM2.'}prefs' => \&prefs,
    'set-{'.NSMAM2.'}prefs' => \&prefs,
);
sub register {
    my ($self,$vhost) = @_;
    my $manage_cb = sub {
	my ($vh, $cb, $iq) = @_;
	return $self unless($vh);
	if(exists $dispatch{$iq->signature}) {
	    $dispatch{$iq->signature}->($self,$iq);
	    return $cb->stop_chain;
	}
	$cb->decline;
    };
    my $handle_cb = sub {
	my ($vh, $cb, $stz) = @_;
	$self->archive($stz) if($stz->isa('DJabberd::Message'));
	$cb->decline;
    };
    $self->{vhost} = $vhost;
    Scalar::Util::weaken($self->{vhost});
    # Owner could only be C2S.
    $vhost->register_hook("c2s-iq",$manage_cb);
    # We want to archive only what was delivered
    $vhost->register_hook("deliver",$handle_cb);
    # Add features
    $vhost->caps->add(DJabberd::Caps::Feature->new(NSMAM0));
    $vhost->caps->add(DJabberd::Caps::Feature->new(NSMAM1));
    $vhost->caps->add(DJabberd::Caps::Feature->new(NSMAM2));
    $vhost->register_hook("DiscoBare",sub {
	my ($vh,$cb,$iq,$disco,$bare,$from,$ri) = @_;
	return $cb->addFeatures(NSMAM0,NSMAM1,NSMAM2)
	    if($disco eq 'info' && $ri && ref($ri) && $ri->subscription->{from});
	$cb->decline;
    });
}

sub vh {
    return $_[0]->{vhost};
}

sub archive {
    my ($self, $msg) = @_;
    return unless(DJabberd::Plugin::Carbons::eligible($msg, 313));
    my @for = $self->archivable($msg);
    return unless(@for && $for[0]);
    my ($body) = grep{$_->element_name eq 'body'}$msg->children_elements;
    # Technically we shouldn't, but as long as we store only body - it's ok
    return unless($body);
    my $ts = Time::HiRes::clock_gettime(CLOCK_REALTIME);
    # We may archive from s2s delivery
    my $arc_el = $body->clone;
    $arc_el->replace_ns('jabber:server','jabber:client');
    my $data = $arc_el->as_xml();
    # We also need to store id and origin-id for sent msgs dedup
    ($arc_el) = grep{$_->element_name eq 'origin-id'}$msg->children_elements;
    $data .= $arc_el->as_xml() if($arc_el);
    my $type = ($msg->{attrs}{'{}type'} || 'normal');
    my $id = $self->store_archive($msg->from, $msg->to, $type, $msg->{attrs}{'{}id'}, $data, $ts, @for);
    $logger->debug("The message was ".(($id)?"stored under $id":"not stored"));
    return unless($id);
    return unless(grep{$msg->to_jid->as_bare_string eq $_->as_bare_string}@for);
    DJabberd::SID::set_sid($msg, $id, $msg->to_jid);
}

sub store_archive {
    my ($self, $from, $rcpt, $type, $oid, $data, $time, @usrs) = @_;
    $logger->warn("Message store not implemented");
    return undef;
}

sub query_archive {
    my $self = shift;
    my $bare = shift;
    my $form = shift;
    my $rsm = shift;
    my @ret = ();
    # ({ ts=>gmtime, from=>jid, to=>jid, id=>stanza_id, body=>xml_string, type=>msg_type, oid=>origin_id},)
    $logger->error("query_archive not implemented");
    return @ret;
}

sub id {
    my $self = shift;
    return Digest::SHA::hmac_sha256_base64("mam".time,$self->{seqid}++);
}

sub check_access {
    my ($self, $node, $jid) = @_;
    return 1 if($node eq $jid->as_bare_string);
    return 0;
}

sub query {
    my $self = shift;
    my $iq = shift;
    my $user = $iq->connection->bound_jid;
    my $node = $iq->to || $user->as_bare_string;
    if(!$self->check_access($node, $user)) {
	$iq->send_error("<error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>");
	return;
    }
    my $query = $iq->query;
    my ($x) = grep{$_->element eq '{jabber:x:data}x'}$query->children_elements;
    my ($r) = grep{$_->element eq $DJabberd::Set::Element}$query->children_elements;
    $logger->debug("Query[".$user->as_string."]: ".($x && $x->as_xml || '').($r && $r->as_xml || ''));
    my $node = $query->attr('{}node');
    my $form = DJabberd::Form->new($x) if($x);
    my $rsm = DJabberd::Set->new($r);
    $rsm->max($rsm->max + 1) if($rsm->max); # more_data indicator
    my @msgs = $self->query_archive($node, $form, $rsm);
    if(@msgs && !defined $msgs[0]) {
	# rsm before/after freaked out results, need to item-not-found
	return $iq->send_error("<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>");
    } elsif(@msgs) {
	if($rsm->max && scalar(@msgs) == $rsm->max) {
	    if(defined $rsm->before && $rsm->before eq '') {
		# reversed query
		shift(@msgs);
	    } else {
		# normal query
		pop(@msgs);
	    }
	    $rsm->has_more(1);
	}
	my %queryid = (queryid=>$query->attr('{}queryid')) if($query->attr('{}queryid'));
	foreach my $msg(@msgs) {
	    my $stanza = DJabberd::Message->new('jabber:client','message',
		{
		    xmlns => 'jabber:client',
		    '{}to' => $user->as_string
		},
		[DJabberd::XMLElement->new($query->namespace, 'result',
		    {
			xmlns => $query->namespace,
			id => $msg->{id},
			%queryid
		    },
		    [
			DJabberd::Plugin::Carbons::wrap_fwd(
			    DJabberd::Delivery::OfflineStorage::delay($msg->{ts}),
			    DJabberd::XMLElement->new('jabber:client', 'message',
				{
				    ($msg->{oid}?(id => $msg->{oid}):()),
				    to => $msg->{to},
				    from => $msg->{from},
				    type => $msg->{type},
				    xmlns => 'jabber:client'
				},
				[], $msg->{body}
			    )
			)
		    ]
		)]
	    );
	    my $xml = $stanza->as_xml;
	    $iq->connection->log_outgoing_data($xml);
	    $iq->connection->write(\$xml);
	}
	$rsm->first($msgs[0]->{id});
	$rsm->last($msgs[-1]->{id});
    } else {
	$rsm->count(undef);
	$rsm->first(undef);
	$rsm->last(undef);
    }
    my %atts = ( xmlns => $query->namespace );
    $atts{complete} = 'true' unless($rsm->{has_more});
    my $fin = DJabberd::XMLElement->new($query->namespace,'fin',\%atts,[$rsm->as_element()]);
    $iq->send_result_raw($fin->as_xml);
}

sub get_prefs {
    my $self = shift;
    my $user = shift;
    # extract from persistent storage
    $logger->warn("Not implemented");
    return (default => $self->{default}, always => [], never => []);
}

sub gen_pref_list {
    my $key = shift;
    my %pref = @_;
    return (@{$pref{always}}) ? 
	    "<$key>".join('',map{"<jid>$_</jid>"}@{$pref{$key}})."</$key>"
	    : "<$key/>";
}
sub prefs {
    my $self = shift;
    my $iq = shift;
    my $prefs = $iq->first_element->clone;
    $logger->debug("Prefs: ".$iq->type);
    if($iq->to && !$iq->connection->bound_jid->eq($iq->to_jid)) {
	$iq->send_error("<error type='cancel'><forbidden></error>");
	return;
    }
    if($iq->type eq 'get') {
	my %pref = $self->get_prefs($iq->connection->bound_jid->as_bare_string);
	$prefs->set_attr('default',$pref{default});
	$prefs->set_raw(gen_pref_list('always',%pref).gen_pref_list('never',%pref));
	$iq->send_result_raw($prefs->as_xml);
    } else {
	$iq->send_error("<error type='cancel'>".
	    "<feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>".
			"</error>");
    }
}

sub grep_jid {
    my $jid = shift;
    return grep {$jid->eq($_) || $jid->as_bare_string eq $_->as_string} map {DJabberd::JID->new($_)} @_;
}

sub check_jid {
    my ($self, $user, $for) = @_;
    if($self->vh->handles_jid($user)) {
	my %pref = $self->get_prefs($user->as_bare_string);
	return ($user) if(grep_jid($for, @{$pref{always}}));
	return () if(grep_jid($for, @{$pref{never}}));
	return ($user) if($pref{default} eq 'always');
	return () if($pref{default} eq 'never');
	# remaining option is - roster. Self is always subscribed.
	return ($user) if($user->as_bare_string eq $for->as_bare_string);
	my $r = { item => undef };
	$self->vh->hook_chain_fast("RosterLoadItem", [$user, $for], {
	    set => sub {
		$r->{item} = $_[1];
	    }
	});
	return ($user) if(ref($r->{item}) && $r->{item}->subscription->sub_to);
    }
    return ();
}

sub archivable {
    my ($self, $msg) = @_;
    return (
	    $self->check_jid($msg->to_jid, $msg->from_jid),
	    $self->check_jid($msg->from_jid, $msg->to_jid)
    );
}

sub strpiso8601time {
    my $str = shift;
    if($str =~ /(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)?/) {
	my $time_t = Time::Local::timegm($6,$5,$4,$3,$2-1,$1);
	my $off_t = 0;
	my $frac = $7 || '';
	if($8 && $8 =~ /([+-])(\d+):(\d+)/) {
	    $off_t = "${1}1" * ($2*60*60 + $3*60);
	}
	return ($time_t + $off_t).$frac;
    }
    return undef;
}

package DJabberd::SID;
use Digest::SHA;

use constant {
    NSSID => 'urn:xmpp:sid:0',
};


sub gen_sid {
    my $time = $_[3] || time;
    return Digest::SHA::hmac_sha256_base64("$_[1]:$time",sprintf("%02d",rand(10)),$_[2]);
}

sub set_sid {
    my $msg = shift;
    my $sid = shift;
    my $jid = shift;
    my @els = $msg->children_elements;
    $msg->set_raw();
    # Filter out *our* stanza-id childs
    for my $el(@els) {
	$msg->push_child($el) unless($el->element eq '{'.NSSID.'}stanza-id' && $el->attr('{}by') eq $jid->as_bare_string);
    }
    $msg->push_child(DJabberd::XMLElement->new(NSSID, 'stanza-id', {
	xmlns => NSSID,
	by => $jid->as_bare_string,
	id => $sid
    }));
}

package DJabberd::Set;

use constant NSRSM => 'http://jabber.org/protocol/rsm';

our $Element = '{'.NSRSM.'}set';

sub new {
    my $class = shift;
    my $arg = shift;
    my $from = {};
    if($arg && ref($arg)) {
	if(ref($arg) eq 'HASH') {
	    $from = $arg;
	} elsif($arg->isa('DJabberd::XMLElement') && $arg->element eq $Element) {
	    foreach my $el($arg->children_elements) {
		if($el->element_name eq 'index') {
		    ($from->{index}) = grep{/\d/}$el->children;
		    $from->{index} += 0;
		} elsif($el->element_name eq 'count') {
		    ($from->{count}) = grep{/\d/}$el->children;
		    $from->{count} += 0;
		} elsif($el->element_name eq 'max') {
		    ($from->{max}) = grep{/\d/}$el->children;
		    $from->{max} += 0;
		} elsif($el->element_name eq 'before') {
		    ($from->{before}) = grep{/\S/}$el->children;
		    $from->{before} = '' unless($from->{before});
		} elsif($el->element_name eq 'after') {
		    ($from->{after}) = grep{/\S/}$el->children;
		    $from->{after} = '' unless($from->{after});
		} elsif($el->element_name eq 'first') {
		    ($from->{first}) = grep{/\S/}$el->children;
		    $from->{index} = $el->attr('{}index')if(defined $el->attr('{}index'));
		} elsif($el->element_name eq 'last') {
		    ($from->{last}) = grep{/\S/}$el->children;
		}
	    }
	}
    }
    my $self = bless $from, $class;
    return $self;
}

sub has_more {
    my $self = shift;
    if(@_) {
	$self->{has_more} = $_[0];
    } else {
	return $self->{has_more};
    }
}

sub max {
    my $self = shift;
    if(@_) {
	$self->{max} = $_[0];
    } else {
	return $self->{max};
    }
}

sub count {
    my $self = shift;
    if(@_) {
	$self->{count} = $_[0];
    } else {
	return $self->{count};
    }
}

sub first {
    my $self = shift;
    if(@_) {
	$self->{first} = $_[0];
    } else {
	return ($self->{first} or '');
    }
}

sub last {
    my $self = shift;
    if(@_) {
	$self->{last} = $_[0];
    } else {
	return ($self->{last} or '');
    }
}

sub before {
    my $self = shift;
    if(@_) {
	$self->{before} = $_[0];
    } else {
	return $self->{before};
    }
}

sub after {
    my $self = shift;
    if(@_) {
	$self->{after} = $_[0];
    } else {
	return $self->{after};
    }
}

sub as_element {
    my $self = shift;
    my %atts = (xmlns=>NSRSM);
    my @kids;
    push(@kids,"<first index=\"".($self->{index} or '0')."\">$self->{first}</first>")
	if($self->{first});
    push(@kids,"<last>$self->{last}</last>") if($self->{last});
    push(@kids,"<count>".($self->{count} or '0')."</count>");
    return DJabberd::XMLElement->new(NSRSM, 'set',
	    {%atts},
	    [],
	    join('',@kids)
    );
}

=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
1;
