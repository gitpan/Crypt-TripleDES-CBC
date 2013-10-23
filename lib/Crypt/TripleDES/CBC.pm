use strict;
use warnings;

package Crypt::TripleDES::CBC;

# PODNAME: Crypt::TripleDES::CBC
# ABSTRACT: Triple DES in CBC mode
#
# This file is part of Crypt-TripleDES-CBC
#
# This software is copyright (c) 2013 by Shantanu Bhadoria.
#
# This is free software; you can redistribute it and/or modify it under
# the same terms as the Perl 5 programming language system itself.
#
our $VERSION = '0.001'; # VERSION

# Dependencies

use Moose;
use 5.010;
use Crypt::DES;


has cipher1 => (
    is         => 'ro',
    lazy_build => 1,
);

sub _build_cipher1 {
    my ($self) = @_;
    my $cipher = new Crypt::DES( substr( $self->key, 0, 8 ) );
}


has cipher2 => (
    is         => 'ro',
    lazy_build => 1,
);

sub _build_cipher2 {
    my ($self) = @_;
    my $cipher = new Crypt::DES( substr( $self->key, 8 ) );
}


has key => (
    is       => 'ro',
    required => 1,
);


has iv => (
    is       => 'ro',
    required => 1,
    default  => pack( "H*", "0000000000000000" ),
);


sub encrypt {
    my ( $self, $cleartext ) = @_;
    my $length = length($cleartext);
    my $result = '';
    my $iv     = $self->iv;
    while ( $length > 8 ) {
        my $block = substr( $cleartext, 0, 8 );
        $cleartext = substr( $cleartext, 8 );
        my $ciphertext = $self->_encrypt_3des( $block ^ $iv );
        $result .= $ciphertext;
        $iv     = $ciphertext;
        $length = length($cleartext);
    }
    my $ciphertext = $self->_encrypt_3des( $cleartext ^ $iv );
    $result .= $ciphertext;
    return $result;
}


sub decrypt {
    my ( $self, $ciphertext ) = @_;
    my $length = length($ciphertext);
    my $result = '';
    my $iv     = $self->iv;
    while ( $length > 8 ) {
        my $block = substr( $ciphertext, 0, 8 );
        $ciphertext = substr( $ciphertext, 8 );
        my $cleartext = $self->_decrypt_3des($block);
        $result .= $cleartext ^ $iv;
        $iv     = $block;
        $length = length($ciphertext);
    }
    my $cleartext = $self->_decrypt_3des($ciphertext);
    $result .= $cleartext ^ $iv;
    return $result;
}

sub _encrypt_3des {
    my ( $self, $plaintext ) = @_;
    return $self->cipher1->encrypt(
        $self->cipher2->decrypt( $self->cipher1->encrypt($plaintext) ) );
}

sub _decrypt_3des {
    my ( $self, $ciphertext ) = @_;
    return $self->cipher1->decrypt(
        $self->cipher2->encrypt( $self->cipher1->decrypt($ciphertext) ) );
}

1;

__END__

=pod

=head1 NAME

Crypt::TripleDES::CBC - Triple DES in CBC mode

=head1 VERSION

version 0.001

=head1 ATTRIBUTES

=head2 cipher1

First Crypt::DES Cipher object generated from the key. This is built automatically.

=head2 cipher2

second Crypt::DES Cipher object generated from the key. This is built automatically.

=head2 key

Encryption Key

=head2 iv

Initialization vector, default is null

=head1 METHODS

=head2 encrypt

Encryption Method

=head2 decrypt

Decryption method

=for :stopwords cpan testmatrix url annocpan anno bugtracker rt cpants kwalitee diff irc mailto metadata placeholders metacpan

=head1 SUPPORT

=head2 Bugs / Feature Requests

Please report any bugs or feature requests through github at 
L<https://github.com/shantanubhadoria/crypt-tripledes-cbc/issues>.
You will be notified automatically of any progress on your issue.

=head2 Source Code

This is open source software.  The code repository is available for
public review and contribution under the terms of the license.

L<https://github.com/shantanubhadoria/crypt-tripledes-cbc>

  git clone git://github.com/shantanubhadoria/crypt-tripledes-cbc.git

=head1 AUTHOR

Shantanu Bhadoria <shantanu at cpan dott org>

=head1 CONTRIBUTOR

Shantanu Bhadoria <shantanu@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by Shantanu Bhadoria.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
