package AUTH;
require Exporter;
@ISA = Exporter;
@EXPORT = qw( Authenticate );

$VERSION = '2013.11.19';

#use lib "/m1/uals/lib";
use AUTH::Alma;
use AUTH::LDAP;
use Alma::User;

my $bc_pattern = '^\d{10}\w$';
my $uni_id_pattern = '^a\d{7}$';

sub Authenticate {
    my ($username, $password) = @_;
    my $data;
    my $authenticated = 'N';

    if ($username =~ /$uni_id_pattern/o) { ## uni_id

        my $result = AUTH::LDAP::Authenticate_with_LDAP( $username, $password );

        if ( $result->{auth} eq 'Y' ) {
            $data = Alma::User::getUser( $result->{instid} );
            $authenticated = 'Y' unless $data->{error};
        }

    }
    else { ## assume Alma id, e.g. barcode

        $data = AUTH::Alma::Authenticate( $username, $password );
	$authenticated = 'Y' unless $data->{error};
    }
    $data->{authenticated} = $authenticated;

    return $data;
}

__END__

=head1 NAME

AUTH.pm

=head1 DESCRIPTION

AUTH.pm authenticates user credentials against the Alma database
and returns hash reference with user details.

=head1 USAGE

    my $data = AUTH::Authenticate( $user, $pass );

=head1 AUTHOR

Steve Thomas <stephen.thomas@adelaide.edu.au>

=head1 VERSION

This is version 2013.11.19

=cut
