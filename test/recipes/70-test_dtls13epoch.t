#! /usr/bin/env perl
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use feature 'state';

use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file bldtop_dir/;
use OpenSSL::Test::Utils;
use TLSProxy::Proxy;
use TLSProxy::Message;

my $test_name = "test_dtlsrecords";
setup($test_name);

plan skip_all => "TLSProxy isn't usable on $^O"
    if $^O =~ /^(VMS)$/;

plan skip_all => "$test_name needs the dynamic engine feature enabled"
    if disabled("engine") || disabled("dynamic-engine");

plan skip_all => "$test_name needs the sock feature enabled"
    if disabled("sock");

plan skip_all => "$test_name needs DTLSv1.3 enabled"
    if disabled("dtls1_3");

my $proxy = TLSProxy::Proxy->new_dtls(
    undef,
    cmdstr(app(["openssl"]), display => 1),
    srctop_file("apps", "server.pem"),
    (!$ENV{HARNESS_ACTIVE} || $ENV{HARNESS_VERBOSE})
);

plan tests => 2;

my $epoch = 0;

#Test 1: Check that epoch is incremented as expected after a handshake
$epoch = 0;
$proxy->serverflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->clientflags("-min_protocol DTLSv1.3 -max_protocol DTLSv1.3");
$proxy->filter(\&current_record_epoch_filter);
TLSProxy::Message->successondata(1);
ok($proxy->start(), "Proxy run succeeded");
ok($epoch == 2, "Epoch after handshake test");

sub current_record_epoch_filter
{
    my $records = $proxy->record_list;
    my $latest_record = @{$records}[-1];
    $epoch = $latest_record->epoch;
}
