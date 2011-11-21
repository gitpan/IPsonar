package IPsonar;

use strict;
use warnings;

use version; 
our $VERSION;
$VERSION = "0.15";

use Net::SSLeay qw(make_headers get_https);
use URI;
use XML::Simple;
use Data::Dumper;
use MIME::Base64;
use LWP::UserAgent;
use Carp;
use constant {
    HTTPS_TCP_PORT    => 443,
    DEFAULT_PAGE_SIZE => 100,
};


=head1 NAME

IPsonar - Wrapper to interact with the Lumeta IPsonar API

=head1 VERSION

Version 0.15

=cut


=head1 SYNOPSIS

This module wraps the IPsonar RESTful API.
It handles the paging and https stuff so you can concentrate on extracting
information from reports.

Code snippet.

    my $rsn = IPsonar->new('rsn_address_or_name','username','password');
    my $test_report = 23;
    my @ip_list;

    my $results = $rsn->query('detail.devices',
        {
            'q.f.report.id'                 =>  $test_report,
            'q.f.servicediscovery.ports'    =>  23,
        }) or die "Problem ".$rsn->error;

    while (my $x = $rsn->next_result) {
        push @ip_list,$x->{ip};
    }

=head1 SUBROUTINES/METHODS

=cut


#-----------------------------------------------------------
# new(rsn, username, password)
=over 8

=item new (rsn, username, password)

=back

Establish connection to a report server using username / password 
Note:  This doesn't actually initiate a connection until you issue
a query.
=cut

sub new {
    my $class    = shift;
    my $self     = {};
    my $rsn      = shift;
    my $username = shift;
    my $password = shift;
    $self->{request} = sub {    #request(query, parameters)
        my $query  = shift;
        my $params = shift;
        _request_using_password( $rsn, $query, $params, $username, $password );
    };
    bless $self, $class;
    return $self;
}

#-----------------------------------------------------------
=over 8

=item new_with_cert (rsn, path_to_cert, password)

=back

Establish connection to a report server using SSL certificate

=cut

sub new_with_cert {
    my $class     = shift;
    my $self      = {};
    my $rsn       = shift;
    my $cert_path = shift;
    my $password  = shift;
    $self->{request} = sub {    #request(query, parameters)
        my $query  = shift;
        my $params = shift;
        _request_using_certificate( $rsn, $query, $params, $cert_path,
            $password );
    };
    bless $self, $class;
    return $self;
}

#-----------------------------------------------------------
=over 8

=item $rsn->query ( method, hashref_of_parameters)

=back

Issue a query (get results for non-paged queries).
If you're getting back paged data we'll return the number of items
available in the query.  If we're getting back a single result we
return a hashref to those results.

=cut

sub query {
    my $self = shift;
    $self->{query}  = shift;
    $self->{params} = shift;

    # Set default parameters (over-riding fmt, it must be XML).
    $self->{params}->{'q.page'} //= 0;
    $self->{params}->{'q.pageSize'} //= DEFAULT_PAGE_SIZE;
    $self->{params}->{fmt} = 'xml';

    #-----------------------------------------------------------
    # instance variables
    #
    # total     The total number of items we could iterate over
    # request   A funcref to the underlying function that gets
    #           our XML back from the server.  It's a funcref
    #           because it can either be password or PKI authentication
    # query     The API call we're making (e.g. "config.reports"
    # params    The API parameters we're passing
    # error     The XML error we got back from IPsonar (if any)
    # page_size The number of items we expect per page
    # paged     Is the result paged (or are we getting a single value)
    # max_page  Maximum page we'll be able to retrieve
    # max_row   Maximum row on this page (0-n).
    #-----------------------------------------------------------

    my $res = $self->{request}( $self->{query}, $self->{params} );

    # KeyAttr => [] because otherwise XML::Simple tries to be clever
    # and hand back a hashref keyed on "id" or "name" instead of an
    # arrayref of items.
    my $xml = XMLin( $res, KeyAttr => [] );

    if ( $xml->{status} ne 'SUCCESS' ) {
        $self->{error} = $xml->{error}->{detail};
        croak $self->{error};
    }

    $self->{xml} = $xml;
    $self->{page_row} = 0;

    if (defined ($xml->{total}) and $xml->{total} == 0 ) {
        $self->{total} = 0;
        $self->{paged} = 1;
        return $xml;
    }

    if ( $xml->{total} && $self->{params}->{'q.pageSize'} ) {    # Paged Data
        $self->{total} = $xml->{total};
        my $page_size = $self->{params}->{'q.pageSize'};

        # Figure out what the key to the array data is
        my $temp = XMLin( $res, NoAttr => 1, KeyAttr => [] );
        my $key = ( keys %{$temp} )[0];
        $self->{pagedata} = $self->{xml}->{$key};
        warn "Key = $key, Self = ".Dumper($self) if ! $self->{xml}->{$key};

        # Setup paging information
        #TODO this is a honking mess, too many special conditions.
        $self->{paged}    = 1;
        $self->{max_page} = int( ($self->{total}-1) / $page_size );

        $self->{max_row} =
            $self->{params}->{'q.page'} < $self->{max_page}
          ? $page_size-1
          : ( ($self->{total} % $page_size) || $page_size ) - 1;

        # There's only one page with $self->{total} items
        if ($self->{params}->{'q.pageSize'} == $self->{total}) {
            $self->{max_row} = $self->{total} - 1;
        }

        # We're looking at things with pagesize 1
        if ($self->{params}->{'q.pageSize'} == 1) {
            $self->{max_row} = 0;
        }

        return $self->{total};
    }
    else {    # Not paged data
        $self->{total} = 0;
        $self->{paged} = 0;
        delete( $self->{key} );
        return $xml;
    }
}

#-----------------------------------------------------------
=over 8

=item $rsn->next_result ()

=back

Get next paged results
=cut

sub next_result {
    my $self = shift;

    #print "page_row: $self->{page_row}, max_row: $self->{max_row}, ".
    #        "page: $self->{params}->{'q.page'}, max_page: $self->{max_page}\n";

    #No results
    return 0 if $self->{total} == 0 && $self->{paged};

    #Not paged data
    return $self->{xml} if !$self->{paged};

    #End of Data
    if ($self->{params}->{'q.page'} == $self->{max_page} &&
        $self->{page_row} > $self->{max_row}) {
            return;
    }

    #End of Page
    if ( $self->{page_row} > $self->{max_row} ) {
        $self->{params}->{'q.page'}++;
        $self->query( $self->{query}, $self->{params} );
    }

    #Single item on last page
    if ( $self->{page_row} == 0 and $self->{max_row} == 0 ) { 
        $self->{page_row}++;
        return $self->{pagedata};
    }

    return $self->{pagedata}[ $self->{page_row}++ ];

}

#-----------------------------------------------------------
=over 8

=item $rsn->error

=back

Get error information
=cut

sub error {
    my $self = shift;
    return $self->{error};
}

#===========================================================
# From API cookbook
###

### These can already be defined in your environment, or you can get
### them from the user on the command line or from stdin.  It's
### probably best to get the password from stdin.

###
### Routine to run a query using authentication via PKI certificate
### Inputs:
###  server - the IPsonar report server
###  method - the method or query name, e.g., getReports
###  params - reference to a hash of parameter name / value pairs
### Output:
###  The page in XML format returned by IPsonar
###
sub _request_using_certificate {
    my ( $server, $method, $params, $cert, $passwd ) = @_;

    my $path = _get_path( $method, $params );    # See "Constructing URLs";
    my $url = "https://${server}${path}";

    local $ENV{HTTPS_PKCS12_FILE}     = $cert;
    local $ENV{HTTPS_PKCS12_PASSWORD} = $passwd;
    my $ua  = LWP::UserAgent->new;
    my $req = HTTP::Request->new( 'GET', $url );
    my $res = $ua->request($req);

    return $res->content;
}

#===========================================================
# From API cookbook
###
### Routine to run a query using authentication via user name and password.
### Inputs:
### server - the IPsonar report server
### method - the method or query name, e.g., initiateScan
### params - reference to a hash of parameter name / value pairs
### uname - the IPsonar user name
### passwd - the IPsonar user's password
### Output:
### The page in XML format returned by IPsonar
###
sub _request_using_password {
    my ( $server, $method, $params, $uname, $passwd ) = @_;
    my $port = HTTPS_TCP_PORT;                  # The usual port for https
    my $path = _get_path( $method, $params );    # See "Constructing URLs"
    my $authstring = MIME::Base64::encode( "$uname:$passwd", q() );
    my ( $page, $result, %headers ) =           # we're only interested in $page
      Net::SSLeay::get_https( $server, $port, $path,
        Net::SSLeay::make_headers( Authorization => 'Basic ' . $authstring ) );
    if (! ($result =~ /OK$/) ) {
        croak $result;
    }
    return ($page);
}

#===========================================================
# From API cookbook
###
### Routine to encode the path part of an API call's URL. The
### path is everything after "https://server".
### Inputs:
###   method - the method or query name, e.g., initiateScan
###   params - reference to a hash of parameter name /value pairs
### Output:
###   The query path with the special characters properly encoded
###
sub _get_path {
    my ( $method, $params ) = @_;
    my $path_start = '/reporting/api/service/';
    my $path = $path_start . $method . q(?);    # all API calls start this way
                                                # Now add parameters
    if ( defined $params ) {
        while ( my ( $p, $v ) = each %{$params} ) {
            if ( $path !~ /[?]$/xms ) {    # ... if this isn't the first param
                $path .= q(&);             # params are separated by &
            }
            $path .= "$p=$v";
        }
    }
    my $encoded = URI->new($path);         # encode the illegal characters
                                           # (eg, space => %20)
    return ( $encoded->as_string );
}

1;

