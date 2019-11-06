# vim: ai sts=4:
package DJabberd::Plugin::MAM::InMemoryOnly;
use strict;
use base 'DJabberd::Plugin::MAM';
use warnings;

use Time::Piece;

our $logger = DJabberd::Log->get_logger();

sub finalize {
    my $self = shift;
    # override retention default from time based to count based
    $self->{retain_num} = 999 unless($self->{retain_num} || $self->{retain_sec});
    $self->SUPER::finalize();
    $self->{__store} = { users => {}, msgs => {}, ring => [], pref => {}, id => 0};
    $logger->error("Retain value is not acceptable for InMem storage") if($self->{retain_num} == -1);
}

sub store_archive {
    my $self = shift;
    my $from = shift;
    my $rcpt = shift;
    my $body = shift;
    my $time = shift;
    my $type = shift;
    my @usrs = @_;
    $logger->debug("Store message from $from to $rcpt at $time for ".join(',',@usrs)." with ".$body);
    my $sid = DJabberd::SID::gen_sid($from,$time,$self->{__store}->{id}++);
    my $msg = {ts=>$time, from=>$from, to=>$rcpt, id=>$sid, body=>$body, type=>$type};
    my $s = $self->{__store};
    # begin transaction
    $s->{msgs}->{$sid} = $msg;
    foreach my$u(@usrs) {
	push(@{ $s->{users}->{$u->as_bare_string}||=[] }, $sid);
    }
    push(@{$s->{ring}},$sid);
    # commit transaction
    # retention / cleanup
    if($self->{retain_num}>0) {
	while(scalar(@{$s->{ring}})>$self->{retain_num}) {
	    my $rs = shift(@{$s->{ring}});
	    delete $s->{msgs}->{$sid};
	}
    } elsif($self->{retain_sec}>0) {
	while($time - $s->{msgs}->{$s->{ring}->[0]}->{ts} > $self->{retain_sec}) {
	    my $rs = shift(@{$s->{ring}});
	    delete $s->{msgs}->{$sid};
	}
    }
    return $sid;
}

sub query_archive {
    my $self = shift;
    my $bare = shift;
    my $form = shift;
    my $rsm = shift;
    my @ret = ();
    # ({ ts=>gmtime, from=>jid, to=>jid, id=>uuid, body=>msg_body, type=>msg_type},)
    my $s = $self->{__store};
    $logger->debug("query_archive[".scalar(@{$s->{users}->{$bare}||=[]})."] for $bare");
    my $after = $rsm->after;
    my $before = $rsm->before;
    # cleanup retention trail, reset conditions
    while(scalar(@{$s->{users}->{$bare}}) && !exists($s->{msgs}->{$s->{users}->{$bare}->[0]})) {
	$after = undef if($after && $after eq $s->{users}->{$bare}->[0]);
	return @ret if($before && $before eq $s->{users}->{$bare}->[0]);
	shift(@{$s->{users}->{$bare}});
    }
    # iterating through user archive
    my ($start, $stop, $jid);
    if($form && $form->field('start') && $form->value('start')) {
	$logger->debug("Start: ".join(',',$form->value('start')));
	$start = DJabberd::Plugin::MAM::strpiso8601time([$form->value('start')]->[0])
    }
    if($form && $form->field('end') && $form->value('end')) {
	$logger->debug("End: ".join(',',$form->value('end')));
	$stop = DJabberd::Plugin::MAM::strpiso8601time([$form->value('end')]->[0])
    }
    if($form && $form->field('with') && $form->value('with')) {
	$logger->debug("By: ".join(',',$form->value('with')));
	$jid = DJabberd::JID->new([$form->value('with')]->[0])
    }
    foreach my$sid(@{$s->{users}->{$bare}}) {
	next if($start && $start > $s->{msgs}->{$sid}->{ts});
	last if($stop && $stop < $s->{msgs}->{$sid}->{ts});
	next if($after);
	last if($before && $before eq $sid);
	if($after && $after eq $sid) {
	    $after = undef;
	    next;
	}
	last if($rsm && $rsm->max && ($#ret+1)==$rsm->max);
	if($jid) {
	    my $m = $s->{msgs}->{$sid};
	    my $from = DJabberd::JID->new($m->{from});
	    my $to = DJabberd::JID->new($m->{to});
	    if($jid->as_string eq $bare) {
		next unless($jid->as_string eq $to->as_bare_string && $jid->as_string eq $from->as_bare_string);
	    } else {
		if($jid->is_bare) {
		    next unless($jid->as_bare_string eq $to->as_bare_string || $jid->as_bare_string eq $from->as_bare_string);
		} else {
		    next unless($jid->eq($to) || $jid->eq($from));
		}
	    }
	}
	push(@ret, $s->{msgs}->{$sid});
	$logger->debug("Message $sid passed filter, adding to response");
    }
    return @ret;
}

sub set_prefs {
    my $self = shift;
    my $user = shift;
    my %pref = @_;
    # save to persistent storage
    $logger->warn("set_pref: saving $user prefs");
    $self->{__store}->{pref}->{$user} = \%pref;
    return %pref;
}

sub get_prefs {
    my $self = shift;
    my $user = shift;
    # fetch from persistent storage
    $logger->debug("Retrieving preferences for user $user");
    return $self->{__store}->{pref}->{$user} 
	if(ref($self->{__store}->{pref}->{$user}));
    return (default => $self->{default}, always => [], never => []);
}

1;
