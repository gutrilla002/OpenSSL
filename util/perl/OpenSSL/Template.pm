#! /usr/bin/env perl
# Copyright 2016-2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Implements the functionality to read one or more template files and run
# them through Text::Template

package OpenSSL::Template;

=head1 NAME

OpenSSL::Template - a private extension of Text::Template

=head1 DESCRIPTION

This provides exactly the functionality from Text::Template, with the
following additions:

=over 4

=item -

The template perl code delimiters (given with the C<DELIMITER> option)
are set to C<{-> and C<-}> by default.

=item -

A few extra functions are offered to be used by the template perl code, see
L</Functions>.

=back

=cut

use File::Basename;
use File::Spec::Functions;
use Text::Template 1.46;

our @ISA = qw(Text::Template);  # parent

sub new {
    my $class = shift;

    # Call the constructor of the parent class.
    my $self = $class->SUPER::new(DELIMITERS => [ '{-', '-}'],
                                  @_ );

    # Add few more attributes
    $self->{_output_off}   = 0; # Default to output hunks

    return bless $self, $class;
}

sub fill_in {
    my $self = shift;
    my %opts = @_;
    my %hash = ( %{$opts{HASH}} );
    delete $opts{HASH};

    $self->SUPER::fill_in(HASH => { quotify1 => \&quotify1,
                                    quotify_l => \&quotify_l,
                                    quotify_arg => \&quotify_arg,
                                    quotify_rule => \&quotify_rule,
                                    output_on => sub { $self->output_on() },
                                    output_off => sub { $self->output_off() },
                                    %hash },
                          %opts);
}

=head2 Functions

=cut

# Override Text::Template's append_text_to_result, as recommended here:
#
# http://search.cpan.org/~mjd/Text-Template-1.46/lib/Text/Template.pm#Automatic_postprocessing_of_template_hunks
sub append_text_to_output {
    my $self = shift;

    if ($self->{_output_off} == 0) {
        $self->SUPER::append_text_to_output(@_);
    }

    return;
}

=begin comment

We lie about the OO nature of output_on() and output_off(), 'cause that's
not how we pass them, see the HASH option used in fill_in() above

=end comment

=over 4

=item output_on()

=item output_off()

Switch on or off template output.  Here's an example usage:

=over 4

 {- output_off() if CONDITION -}
 whatever
 {- output_on() if CONDITION -}

=back

In this example, C<whatever> will only become part of the template output
if C<CONDITION> is true.

=back

=cut

sub output_on {
    my $self = shift;
    if (--$self->{_output_off} < 0) {
        $self->{_output_off} = 0;
    }
}

sub output_off {
    my $self = shift;
    $self->{_output_off}++;
}

# Helper functions for the templates #################################

# It might be practical to quotify some strings and have them protected
# from possible harm.  These functions primarily quote things that might
# be interpreted wrongly by a perl eval.

# NOTE THAT THESE AREN'T CLASS METHODS!

=over 4

=item quotify1 STRING

This adds quotes (") around the given string, and escapes any $, @, \,
" and ' by prepending a \ to them.

=back

=cut

sub quotify1 {
    my $s = shift @_;
    $s =~ s/([\$\@\\"'])/\\$1/g;
    '"'.$s.'"';
}

=over 4

=item quotify_l LIST

For each defined element in LIST (i.e. elements that aren't undef), have
it quotified with 'quotify1'.
Undefined elements are ignored.

=back

=cut

sub quotify_l {
    map {
        if (!defined($_)) {
            ();
        } else {
            quotify1($_);
        }
    } @_;
}

=over 4

=item quotify_arg STRING

This put the string between double-quotes if it contains space.

=back

=cut

# quotify_arg STRING
# Enclose string in double-quotes if it contains space
sub quotify_arg {
    my $s = shift @_;
    if (index($s, ' ') != -1) {
       '"'.$s.'"';
    } else {
       $s;
    }
}

=over 4

=item quotify_rule STRING

This escapes spaces with a backslash, to be used with filenames
in GNU Make dependency rules.

=back

=cut

# quotify_rule STRING
# Escape spaces with backslash for GNU Make dependency rules
sub quotify_rule {
    my $s = shift @_;
    $s =~ s{ }{\\ }g;
    $s;
}

=head1 SEE ALSO

L<Text::Template>

=head1 AUTHORS

Richard Levitte E<lt>levitte@openssl.orgE<gt>

=head1 COPYRIGHT

Copyright 2016-2019 The OpenSSL Project Authors. All Rights Reserved.

Licensed under the Apache License 2.0 (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
L<https://www.openssl.org/source/license.html>.

=cut
