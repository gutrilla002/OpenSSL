#! /usr/bin/env perl
# Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

my $NUMBER      = 0x0001;
my $UPPER       = 0x0002;
my $LOWER       = 0x0004;
my $UNDER       = 0x0100;
my $PUNCTUATION = 0x0200;
my $WS          = 0x0010;
my $ESC         = 0x0020;
my $QUOTE       = 0x0040;
my $DQUOTE      = 0x0400;
my $COMMENT     = 0x0080;
my $FCOMMENT    = 0x0800;
my $EOF         = 0x0008;
my @V_def;
my @V_w32;

my $v;
my $c;
foreach (0 .. 127) {
    $c = sprintf("%c", $_);
    $v = 0;
    $v |= $NUMBER      if $c =~ /[0-9]/;
    $v |= $UPPER       if $c =~ /[A-Z]/;
    $v |= $LOWER       if $c =~ /[a-z]/;
    $v |= $UNDER       if $c =~ /_/;
    $v |= $PUNCTUATION if $c =~ /[!\.%&\*\+,\/;\?\@\^\~\|-]/;
    $v |= $WS          if $c =~ /[ \t\r\n]/;
    $v |= $ESC         if $c =~ /\\/;
    $v |= $QUOTE       if $c =~ /['`"]/;         # for emacs: "`'
    $v |= $COMMENT     if $c =~ /\#/;
    $v |= $EOF         if $c =~ /\0/;
    push(@V_def, $v);

    $v = 0;
    $v |= $NUMBER      if $c =~ /[0-9]/;
    $v |= $UPPER       if $c =~ /[A-Z]/;
    $v |= $LOWER       if $c =~ /[a-z]/;
    $v |= $UNDER       if $c =~ /_/;
    $v |= $PUNCTUATION if $c =~ /[!\.%&\*\+,\/;\?\@\^\~\|-]/;
    $v |= $WS          if $c =~ /[ \t\r\n]/;
    $v |= $DQUOTE      if $c =~ /["]/;           # for emacs: "
    $v |= $FCOMMENT    if $c =~ /;/;
    $v |= $EOF         if $c =~ /\0/;
    push(@V_w32, $v);
}

# Output year depends on the year of the script.
my $YEAR = [localtime([stat($0)]->[9])]->[5] + 1900;

print <<"EOF";
/*
 * WARNING: do not edit!
 * Generated by crypto/conf/keysets.pl
 *
 * Copyright 1995-$YEAR The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define CONF_NUMBER       $NUMBER
#define CONF_UPPER        $UPPER
#define CONF_LOWER        $LOWER
#define CONF_UNDER        $UNDER
#define CONF_PUNCT        $PUNCTUATION
#define CONF_WS           $WS
#define CONF_ESC          $ESC
#define CONF_QUOTE        $QUOTE
#define CONF_DQUOTE       $DQUOTE
#define CONF_COMMENT      $COMMENT
#define CONF_FCOMMENT     $FCOMMENT
#define CONF_EOF          $EOF
#define CONF_ALPHA        (CONF_UPPER|CONF_LOWER)
#define CONF_ALNUM        (CONF_ALPHA|CONF_NUMBER|CONF_UNDER)
#define CONF_ALNUM_PUNCT  (CONF_ALPHA|CONF_NUMBER|CONF_UNDER|CONF_PUNCT)

#define KEYTYPES(c)       ((const unsigned short *)((c)->meth_data))

#ifndef CHARSET_EBCDIC
# define CVT(a) ((unsigned char)(a) <= 127 ? (unsigned char)(a) : 127)
#else
# define CVT(a) os_toascii[(unsigned char)(a)]
#endif

/*
 * Attention: because the macro argument 'a' is evaluated twice in CVT(a),
 * it is not allowed pass 'a' arguments with side effects to IS_*(c,a)
 * like for example IS_*(c, *p++).
 */
#define IS_COMMENT(c,a)     ((KEYTYPES(c)[CVT(a)] & CONF_COMMENT) ? 1 : 0)
#define IS_FCOMMENT(c,a)    ((KEYTYPES(c)[CVT(a)] & CONF_FCOMMENT) ? 1 : 0)
#define IS_EOF(c,a)         ((KEYTYPES(c)[CVT(a)] & CONF_EOF) ? 1 : 0)
#define IS_ESC(c,a)         ((KEYTYPES(c)[CVT(a)] & CONF_ESC) ? 1 : 0)
#define IS_NUMBER(c,a)      ((KEYTYPES(c)[CVT(a)] & CONF_NUMBER) ? 1 : 0)
#define IS_WS(c,a)          ((KEYTYPES(c)[CVT(a)] & CONF_WS) ? 1 : 0)
#define IS_ALNUM(c,a)       ((KEYTYPES(c)[CVT(a)] & CONF_ALNUM) ? 1 : 0)
#define IS_ALNUM_PUNCT(c,a) ((KEYTYPES(c)[CVT(a)] & CONF_ALNUM_PUNCT) ? 1 : 0)
#define IS_QUOTE(c,a)       ((KEYTYPES(c)[CVT(a)] & CONF_QUOTE) ? 1 : 0)
#define IS_DQUOTE(c,a)      ((KEYTYPES(c)[CVT(a)] & CONF_DQUOTE) ? 1 : 0)

EOF

my $i;

print "static const unsigned short CONF_type_default[128] = {";
for ($i = 0; $i < 128; $i++) {
    print "\n   " if ($i % 8) == 0;
    printf " 0x%04X,", $V_def[$i];
}
print "\n};\n\n";

print "static const unsigned short CONF_type_win32[128] = {";
for ($i = 0; $i < 128; $i++) {
    print "\n   " if ($i % 8) == 0;
    printf " 0x%04X,", $V_w32[$i];
}
print "\n};\n";
