
=head1 NAME

AUTH::Alma.pm

=head1 DESCRIPTION

AUTH::Alma authenticates user credentials against the Alma database
and returns hash reference with user details.

=head1 USAGE

    my $data = AUTH::Alma::Authenticate( $user, $pass );

=head1 AUTHOR

Steve Thomas <stephen.thomas@adelaide.edu.au>

=head1 VERSION

This is version 2013.11.20

=cut

package AUTH::Alma;

#require Exporter;
#@ISA = Exporter;
#@EXPORT = qw( );

$VERSION = '2013.11.20';

use lib "/m1/uals/lib";
use Alma::User;

sub Authenticate {
    my ($id, $pass) = @_;

    my $data = Alma::User::getUser( $id );

    VERIFY: {
	if ( $data->{error} ) { last; } 

	## Allow for user id being the primary identifier
	if ( $data->{userDetails}->{userName} eq  $id
	and  $data->{userDetails}->{lastName} =~ /$pass/i
	and  $data->{userDetails}->{status} eq 'Active' ) {
	    last VERIFY; 
	} 

	## scan our list of identifiers until we find a match
	foreach my $b ( @{ $data->{userIdentifiers}->{userIdentifier} } ) {
	    if ( $b->{value} eq $id
	    and  $b->{type} eq 'BARCODE'
	    and  $b->{status} eq 'Active'
	    and  $data->{userDetails}->{lastName} =~ /$pass/i
	    and  $data->{userDetails}->{status} eq 'Active'
	    ) {
		last VERIFY;
	    }
	}

	## Actually, identifier must be valid to get this far, but ...
	$data->{error} = 'Invalid password or identifier not found or identifier not active';
    }

    return $data;
}

__END__
