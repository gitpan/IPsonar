#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 5;
use Data::Dumper;
use IPsonar;
use 5.10.0;

my $results;

my $rsn = IPsonar->_new_with_file('t/test1_2.data');

my @reports = $rsn->reports;
my $r       = $reports[0];

is( 30,  scalar(@reports), "We should have 30 reports" );
is( 152, $r->{ipcount},    "We should have 152 IPs in report 1" );
is(
    'Wed Feb 26 08:59:23 2014',
    localtime( $r->{timestamp} ),
    "Check timestamp"
);
is( "testhdstitch", $r->{name},  "Checking name" );
is( "testhdstitch", $r->{title}, "Checking title" );

