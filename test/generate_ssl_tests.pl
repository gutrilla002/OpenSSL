#! /usr/bin/perl
# -*- mode: perl; -*-

## SSL testcase generator

use strict;
use warnings;

use File::Basename;
use File::Spec::Functions;

use lib catdir(dirname(__FILE__),"../util");  # for with_fallback
use lib catdir(dirname(__FILE__),"ssl-tests");  # for ssltests_base

use with_fallback qw(Text::Template);

use vars qw/@ISA/;
push (@ISA, qw/Text::Template/);

use ssltests_base;

sub print_templates {
    my $template = Text::Template->new(TYPE => 'FILE', SOURCE => "ssl_test.tmpl");

    print "# Generated with generate_ssl_tests.pl\n\n";

    my $num = scalar @ssltests::tests;

    # Add the implicit base configuration.
    foreach my $test (@ssltests::tests) {
        $test->{"server"} = { (%ssltests::base_server, %{$test->{"server"}}) };
        $test->{"client"} = { (%ssltests::base_client, %{$test->{"client"}}) };
    }

    # ssl_test expects to find a
    #
    # num_tests = n
    #
    # directive in the file. It'll then look for configuration directives
    # for n tests, that each look like this:
    #
    # test-n = test-section
    #
    # [test-section]
    # (SSL modules for client and server configuration go here.)
    #
    # [test-n]
    # (Test configuration goes here.)
    print "num_tests = $num\n\n";

    # The conf module locations must come before everything else, because
    # they look like
    #
    # test-n = test-section
    #
    # and you can't mix and match them with sections.
    my $idx = 0;

    foreach my $test (@ssltests::tests) {
        my $testname = "${idx}-" . $test->{'name'};
        print "test-$idx = $testname\n";
        $idx++;
    }

    $idx = 0;

    foreach my $test (@ssltests::tests) {
        my $testname = "${idx}-" . $test->{'name'};
        my $text = $template->fill_in(
            HASH => [{ idx => $idx, testname => $testname } , $test],
            DELIMITERS => [ "{-", "-}" ]);
        print "# ===========================================================\n\n";
        print "$text\n";
        $idx++;
    }
}

# Shamelessly copied from Configure.
sub read_config {
    my $fname = shift;
    open(INPUT, "< $fname")
	or die "Can't open input file '$fname'!\n";
    my $x = $/;
    undef $/;
    my $content = <INPUT>;
    $/ = $x;
    close(INPUT);
    eval $content;
    warn $@ if $@;
}

my $input_file = shift;
# Reads the tests into ssltests::tests.
read_config($input_file);
print_templates();

1;
