package AUTH::LDAP;
require Exporter;
@ISA = Exporter;
@EXPORT = qw( Authenticate_with_LDAP );

$VERSION = '2013.08.24';

sub Authenticate_with_LDAP {
    my ($user, $pass) = @_;

    my $result = { auth => 'N' };

    use Net::LDAP; 
    my $ldap_server = "ldap.adelaide.edu.au"; 
    my $ldap_base = "ou=people,dc=adelaide,dc=edu,dc=au";

    my $ldap = Net::LDAP->new("$ldap_server", scheme=>'ldaps', debug=>0)
	or die "$@";

    my $dn = "uid=$user,$ldap_base";

    my $mesg = $ldap->bind("$dn", password => "$pass");

    unless ( $mesg->code eq Net::LDAP::LDAP_SUCCESS ) {
	$result->{mesg} = $mesg->error;
	return $result;
    }

    # At this point, we're authenticated against LDAP.
    # But now we need to get the insitution id for Voyager.

    $mesg = $ldap->search(
	base	=> $ldap_base,
	scope	=> "subtree",
	attrs	=> [qw(
	    employeenumber division section departmentnumber 
	    preferredname sn mail
	    telephonenumber facsimiletelephonenumber
	)],
	filter	=> "(uid=$user)"
    );

    if ($mesg->code) {
	# search failed -- which should never happen at this point
	$result->{mesg} = $mesg->error;
	return $result;
    }

    my @entries = $mesg->entries;

    if ($DEBUG) {
	print "Content-type: text/plain\n\n";
	foreach my $entry (@entries) { $entry->dump; }
    }

    my $max = $mesg->count;

    if ($max == 1) {
	my $entry = $entries[0];
	$result->{auth}     = 'Y';
	$result->{dept}     = $entry->get_value('departmentnumber');
	$result->{name}     = $entry->get_value('preferredname');
	$result->{lastname} = $entry->get_value('sn');
	$result->{email}    = $entry->get_value('mail');
	$result->{phone}    = $entry->get_value('telephonenumber');
	$result->{fax}      = $entry->get_value('facsimiletelephonenumber');
	$result->{instid}   = $entry->get_value('employeenumber');
    }

    $ldap->unbind();

    return $result;
}


1;

__END__

=head1 NAME

AUTH::LDAP

=head1 DESCRIPTION

AUTH::LDAP authenticates user credentials and returns hash reference
with user details.

=head1 USAGE

    my $result = AUTH::LDAP::Authenticate_with_LDAP( $user, $pass );

=head1 AUTHOR

Steve Thomas <stephen.thomas@adelaide.edu.au>

=head1 VERSION

This is version 2013.08.24

=cut
